mod common;

#[test]
fn test_check_deps() -> Result<(), anyhow::Error> {
    check_json_output!(
        "basic_monorepo",
        "npm@10.5.0",
        "check-deps",
        "check dependencies" => [],
    );

    Ok(())
}
