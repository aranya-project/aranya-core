#[test]
fn test_default() {
    assert_eq!(1 + 1, 2);
}

#[cfg_attr(docs, doc(cfg(feature = "spira")))]
#[cfg(feature = "spira")]
mod spira {
    use core::result::Result;

    #[test]
    #[rtrack::spira(
        project_id = 42,
        test_cases = [1, 2, 3],
    )]
    fn test_unit() {
        assert_eq!(1 + 2, 3);
    }

    #[test]
    #[rtrack::spira(
        project_id = 1,
        test_cases = [123],
    )]
    fn test_result() -> Result<(), ()> {
        if 1 + 2 == 3 {
            Ok(())
        } else {
            Err(())
        }
    }

    #[test]
    #[rtrack::spira(
        project_id = 1,
        test_cases = [123],
    )]
    #[should_panic]
    fn test_panic() {
        panic!("oops");
    }
}
