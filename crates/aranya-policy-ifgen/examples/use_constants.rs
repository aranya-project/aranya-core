#[path = "../tests/data/constants.rs"]
pub mod constants;

#[allow(clippy::dbg_macro, reason = "example")]
fn main() {
    dbg!(constants::g_bool);
    dbg!(constants::g_enum);
    dbg!(constants::g_int);
    dbg!(constants::g_some);
    dbg!(constants::g_string);
    dbg!(constants::g_struct);
}
