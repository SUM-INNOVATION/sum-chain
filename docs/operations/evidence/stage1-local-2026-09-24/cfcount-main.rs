// Read-only inventory: every column family, its row count and a sha256 over
// its keys and values in iteration order. Opens with the families the
// directory itself lists, so it is independent of any node binary.
use rocksdb::{IteratorMode, Options, DB};
use sha2::{Digest, Sha256};
fn main() {
    let path = std::env::args().nth(1).expect("usage: cfcount <db-dir>");
    let cfs = DB::list_cf(&Options::default(), &path).expect("list_cf");
    let db = DB::open_cf_for_read_only(&Options::default(), &path, &cfs, false).expect("open read-only");
    let (mut total, mut nonempty) = (0u64, 0u32);
    for name in &cfs {
        let cf = db.cf_handle(name).unwrap();
        let (mut n, mut h) = (0u64, Sha256::new());
        for kv in db.iterator_cf(cf, IteratorMode::Start) {
            let (k, v) = kv.unwrap();
            h.update((k.len() as u64).to_le_bytes()); h.update(&k);
            h.update((v.len() as u64).to_le_bytes()); h.update(&v);
            n += 1;
        }
        if n > 0 { nonempty += 1; println!("{name}\t{n}\t{:x}", h.finalize()); }
        total += n;
    }
    println!("# families={} nonempty={} rows={}", cfs.len(), nonempty, total);
}
