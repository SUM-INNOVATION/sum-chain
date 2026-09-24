// Read-only local probe: what does an older binary's open path see when the
// database was last opened by HEAD (which carries one extra column family)?
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
fn main() {
    let dir = std::env::args().nth(1).expect("dir");
    let path = format!("{dir}/db");
    let _ = std::fs::remove_dir_all(&dir);
    {
        let db = sumchain_storage::Database::open_default(&path).expect("HEAD open");
        drop(db);
    }
    let head_cfs: Vec<&str> = sumchain_storage::db::ALL_CFS.to_vec();
    let old_cfs: Vec<&str> = head_cfs.iter().copied().filter(|c| *c != "application_journal").collect();
    println!("HEAD CFs: {}, simulated-old CFs: {}", head_cfs.len(), old_cfs.len());
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    let descs = |v: &Vec<&str>| v.iter().map(|n| ColumnFamilyDescriptor::new(*n, Options::default())).collect::<Vec<_>>();
    match DB::open_cf_descriptors(&opts, &path, descs(&old_cfs)) {
        Ok(_) => println!("OLD-SET OPEN: OK"),
        Err(e) => {
            let m = e.to_string();
            let l = m.to_lowercase();
            let corr = l.contains("corruption") || l.contains("checksum") || l.contains("manifest") || l.contains("current") || l.contains("invalid argument");
            println!("OLD-SET OPEN ERROR: {m}");
            println!("is_corruption_error would return: {corr}");
            let mut ro = Options::default(); ro.create_if_missing(false);
            match DB::repair(&ro, &path) { Ok(()) => println!("DB::repair: OK"), Err(e) => println!("DB::repair ERR: {e}") }
            match DB::open_cf_descriptors(&opts, &path, descs(&old_cfs)) {
                Ok(_) => println!("REOPEN AFTER REPAIR: OK"),
                Err(e) => println!("REOPEN AFTER REPAIR ERROR: {e}"),
            }
        }
    }
    let listed = DB::list_cf(&Options::default(), &path).unwrap();
    println!("CFs on disk after all of the above: {}; application_journal present: {}", listed.len(), listed.iter().any(|c| c == "application_journal"));
}
