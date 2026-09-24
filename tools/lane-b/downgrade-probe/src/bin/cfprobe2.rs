// With data: HEAD writes rows (flushed to SST) into several CFs incl. application_journal;
// then the older binary's open path (CF list minus application_journal, auto_repair) runs.
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
fn main() {
    let dir = std::env::args().nth(1).expect("dir");
    let path = format!("{dir}/db");
    let _ = std::fs::remove_dir_all(&dir);
    let head_cfs: Vec<&str> = sumchain_storage::db::ALL_CFS.to_vec();
    {
        let db = sumchain_storage::Database::open_default(&path).expect("HEAD open");
        for i in 0..2000u32 {
            let k = i.to_be_bytes();
            db.put("blocks", &k, b"block-row").unwrap();
            db.put("state", &k, b"state-row").unwrap();
            db.put("meta", &k, b"meta-row").unwrap();
            db.put("application_journal", &k, b"journal-row").unwrap();
        }
        db.flush().unwrap();
        for i in 2000..2100u32 { db.put("state", &i.to_be_bytes(), b"wal-only-row").unwrap(); }
    }
    let old_cfs: Vec<&str> = head_cfs.iter().copied().filter(|c| *c != "application_journal").collect();
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    let descs = |v: &Vec<&str>| v.iter().map(|n| ColumnFamilyDescriptor::new(*n, Options::default())).collect::<Vec<_>>();
    let e = DB::open_cf_descriptors(&opts, &path, descs(&old_cfs)).err().expect("expected refusal");
    println!("OLD-SET OPEN ERROR: {e}");
    let before = DB::list_cf(&Options::default(), &path).unwrap();
    let mut ro = Options::default(); ro.create_if_missing(false);
    DB::repair(&ro, &path).expect("repair");
    let after = DB::list_cf(&Options::default(), &path).unwrap();
    let added: Vec<_> = after.iter().filter(|c| !before.contains(c)).collect();
    let removed: Vec<_> = before.iter().filter(|c| !after.contains(c)).collect();
    println!("repair: CFs before={} after={} removed={:?} added={:?}", before.len(), after.len(), removed, added);
    let db = DB::open_cf_descriptors(&opts, &path, descs(&old_cfs)).expect("reopen after repair");
    for cf in ["blocks", "state", "meta"] {
        let h = db.cf_handle(cf).unwrap();
        let n = db.iterator_cf(&h, rocksdb::IteratorMode::Start).count();
        println!("rows in {cf} after repair: {n}");
    }
    let lost: Vec<String> = after.iter().filter(|c| !old_cfs.contains(&c.as_str()) && c.as_str() != "default").cloned().collect();
    println!("CFs present on disk but not opened by old set: {:?}", lost);
}
