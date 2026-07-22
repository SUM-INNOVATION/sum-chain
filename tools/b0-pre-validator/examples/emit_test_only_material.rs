//! TEST_ONLY: print the frozen synthetic verifier-material JSON for one candidate so
//! the DRY-RUN producer path can populate a sealed per-arch evidence bundle without a
//! real venue. This is `test_only_venue_outputs()` — NON_SELECTION synthetic material,
//! never authoritative and unable to finalize (the bundle it lands in is TEST_ONLY).
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let v = b0_pre_validator::schema::stage6::test_only_venue_outputs();
    match args.first().map(String::as_str) {
        Some("sp1") => print!("{}", v.sp1_extractor_json),
        Some("risc0") => print!("{}", v.risc0_extractor_json),
        _ => {
            eprintln!("usage: emit_test_only_material <sp1|risc0>");
            std::process::exit(2);
        }
    }
}
