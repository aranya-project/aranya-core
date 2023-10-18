use std::{
    env,
    fs::File,
    io::{Result, Write},
    path::Path,
};

use quote::quote;

fn main() -> Result<()> {
    let opt_level = option_env!("OPT_LEVEL");

    let out_dir = env::var("OUT_DIR").expect("invalid env var: `OUT_DIR`");
    let path = Path::new(&out_dir).join("build_info.rs");
    let mut f = File::create(path)?;
    let ts = quote! {
        pub(crate) const OPT_LEVEL: Option<&str> = #opt_level;
    };
    println!("out: {}", ts);
    // write!(&mut f, "{}", ts)?;
    writeln!(&mut f, "pub(crate) const OPT_LEVEL: Option<&str> = None;")?;
    Ok(())
}
