use hoot_polars::HootParser;

#[test]
fn committed_synthetic_fixture_decodes() {
    let bytes = include_bytes!("fixtures/synthetic-two-double.hoot");
    let frame = HootParser::from_bytes(bytes.to_vec()).expect("synthetic fixture must decode");

    assert_eq!(frame.get_column_names_str(), ["timestamp", "x"]);
    assert_eq!(frame.height(), 2);
    assert_eq!(
        frame
            .column("x")
            .expect("x column")
            .f64()
            .expect("f64 column")
            .get(1),
        Some(2.0)
    );
}
