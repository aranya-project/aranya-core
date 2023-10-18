//! Configuration for the Spira integration.

/// Retrieves a configuration value.
///
/// # Example
///
/// ```ignore
/// let _ = crate::spira::config::getcfg!(SPIRA_API_KEY);
/// ```
macro_rules! getcfg {
    (SPIRA_API_KEY) => {
        $crate::spira::config::getenv!(SPIRA_API_KEY)
    };
    (SPIRA_API_USERNAME) => {
        $crate::spira::config::getenv!(SPIRA_API_USERNAME)
    };
    (SPIRA_RECORDER) => {
        $crate::spira::config::getenv!(SPIRA_RECORDER)
    };
    (SPIRA_BASE_URL) => {
        $crate::spira::config::getenv!(SPIRA_BASE_URL)
    };
    (SPIRA_RELEASE_ID) => {
        $crate::spira::config::i32_option_env!("SPIRA_RELEASE_ID")
    };
    (SPIRA_BUILD_ID) => {
        $crate::spira::config::i32_option_env!("SPIRA_BUILD_ID")
    };
    ($name:ident) => {
        ::compile_error!(::concat!("unknown config value: ", ::stringify!($name)))
    };
}
pub(crate) use getcfg;

/// Retrieves an environment variable.
macro_rules! getenv {
    ($name:ident) => {{
        ::std::env::var(::core::stringify!($name)).expect(::core::concat!(
            "invalid env var: ",
            ::core::stringify!($name)
        ))
    }};
}
pub(crate) use getenv;

/// Reads an optional `i32` at compile time.
macro_rules! i32_option_env {
    ($name:expr) => {{
        match ::core::option_env!($name) {
            ::core::option::Option::Some(s) => {
                ::core::option::Option::Some(s.parse::<i32>().expect("invalid `i32`"))
            }
            ::core::option::Option::None => ::core::option::Option::None,
        }
    }};
}
pub(crate) use i32_option_env;
