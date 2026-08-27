use std::path::PathBuf;

use hoot_polars::HootParser;

#[test]
#[ignore = "requires a maintainer-authorized HOOT_TEST_INPUT"]
fn authorized_external_input_is_readable() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os("HOOT_TEST_INPUT").map(PathBuf::from) else {
        eprintln!("skipped: HOOT_TEST_INPUT is not set");
        return Ok(());
    };
    if !path.is_file() {
        return Err(format!("HOOT_TEST_INPUT is not a file: {}", path.display()).into());
    }

    let bytes = std::fs::read(&path)?;
    let report = HootParser::inspect(&bytes)?;
    if report.raw_frames == 0 {
        return Err("input contains no physical records".into());
    }

    eprintln!(
        "decoded {} physical records and {} signal definitions",
        report.raw_frames,
        report.schema.len()
    );
    Ok(())
}
