// Compute the genesis block hash / state root a node would derive from a genesis file.
fn main() {
    for f in std::env::args().skip(1) {
        match sumchain_genesis::Genesis::from_file(&f) {
            Ok(g) => {
                let sr = g.compute_state_root().map(|h| h.to_string()).unwrap_or_else(|e| format!("ERR {e}"));
                let bh = g.create_genesis_block().map(|b| b.hash().to_string()).unwrap_or_else(|e| format!("ERR {e}"));
                println!("{f}\n  chain_id={} state_root={sr}\n  genesis_block_hash={bh}", g.chain_id);
            }
            Err(e) => println!("{f}\n  LOAD ERROR: {e}"),
        }
    }
}
