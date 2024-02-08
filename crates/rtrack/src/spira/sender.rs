use std::{
    fs::{File, OpenOptions},
    io::{self, Stdout, Write},
    path::Path,
    time::Duration,
};

use anyhow::Context;
use reqwest::{blocking::Client, header::HeaderMap, tls};

use crate::spira::api::TestRun;

/// Sends test run information somewhere.
pub(crate) trait Sender {
    fn send(&mut self, r: &TestRun<'_>) -> anyhow::Result<()>;
    fn flush(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Combines multiple [`Sender`]s.
pub(crate) fn tee<I>(senders: I) -> Tee
where
    I: IntoIterator<Item = Box<dyn Sender>>,
{
    Tee {
        senders: senders.into_iter().collect(),
    }
}

/// Returned by [`tee`].
pub(crate) struct Tee {
    senders: Vec<Box<dyn Sender>>,
}

impl Sender for Tee {
    fn send(&mut self, r: &TestRun<'_>) -> anyhow::Result<()> {
        for s in &mut self.senders {
            s.send(r)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        for s in &mut self.senders {
            s.flush()?;
        }
        Ok(())
    }
}

/// Sends results to the SpiraTeam API.
pub(crate) struct Http {
    base_url: String,
    client: Client,
    // Cache for repeated calls to `send`.
    project_id: i32,
    url: Option<String>,
}

impl Http {
    pub fn new(base_url: String, username: String, api_key: String) -> anyhow::Result<Self> {
        let client = Client::builder()
            .default_headers({
                let mut m = HeaderMap::new();
                m.insert("Accept", "application/json".parse()?);
                m.insert("username", username.parse()?);
                m.insert("api-key", api_key.parse()?);
                m
            })
            // TODO(eric): allow HTTP for local debugging.
            .https_only(true)
            // TODO(eric): if Spira supports TLSv1.3, make that
            // the floor.
            .min_tls_version(tls::Version::TLS_1_2)
            // TODO(eric): make this configurable.
            .timeout(Duration::from_secs(60))
            .user_agent("SpiderOak rtrack")
            .build()?;

        Ok(Self {
            base_url,
            client,
            project_id: 0,
            url: None,
        })
    }
}

impl Sender for Http {
    fn send(&mut self, r: &TestRun<'_>) -> anyhow::Result<()> {
        if r.project_id != self.project_id {
            self.project_id = r.project_id;
            self.url = None;
        }
        let url = self.url.get_or_insert_with(|| {
            format!(
                "{}/services/v7_0/RestService.svc/projects/{}/test-runs/record",
                self.base_url, r.project_id,
            )
        });

        let _ = self
            .client
            .post(&*url)
            .json(r)
            .send()
            .context("request failed")?
            .json::<TestRun<'_>>()
            .context("unable to encode response as JSON")?;
        Ok(())
    }
}

/// Sends results to `W`.
pub(crate) struct Writer<W>(W);

impl<W: Write> Writer<W> {
    pub fn new(w: W) -> Self {
        Self(w)
    }
}

impl Writer<Stdout> {
    pub fn stdout() -> Self {
        Self::new(io::stdout())
    }
}

impl Writer<File> {
    pub fn file<P: AsRef<Path>>(name: P) -> anyhow::Result<Self> {
        let file = OpenOptions::new().append(true).open(name)?;
        Ok(Self::new(file))
    }
}

impl<W: Write> Sender for Writer<W> {
    fn send(&mut self, r: &TestRun<'_>) -> anyhow::Result<()> {
        let body = serde_json::to_string_pretty(r).context("unable to encode `TestRun`")?;
        writeln!(&mut self.0, "{body}").context("unable to write to writer")?;
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        Ok(self.0.flush()?)
    }
}
