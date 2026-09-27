//! iron-bootstrap against a live fastetcd (#25). Ignored by default; run with
//! `IRON_BOOTSTRAP_LIVE_ENDPOINT=http://etcd.g8.lo:2379 OPENSSL_CONF=<fips.cnf>
//! cargo test -p iron-bootstrap --test live_bootstrap -- --ignored`.
//! Uses a fresh partition id per run and deletes its keys afterwards.

use std::time::Duration;

use iron_bootstrap::{provision, wait_for_store, Settings};
use iron_partition::Dn;

fn settings(endpoint: &str, pid: &str) -> Settings {
    Settings {
        endpoint: endpoint.to_string(),
        partition_id: pid.to_string(),
        base_dn: Dn::parse(&format!("dc={pid},dc=example,dc=lo")).unwrap(),
        realm: format!("{}.EXAMPLE.LO", pid.to_ascii_uppercase()),
        netbios_name: pid.to_ascii_uppercase(),
        admin_password: b"TestPass123!".to_vec(),
    }
}

async fn cleanup(endpoint: &str, pid: &str) {
    let mut c = etcd_client::Client::connect([endpoint], None).await.unwrap();
    for p in [pid.to_string(), format!("{pid}-config"), format!("{pid}-schema")] {
        c.delete(format!("/iron/{p}/"), Some(etcd_client::DeleteOptions::new().with_prefix())).await.unwrap();
    }
}

#[tokio::test]
#[ignore]
async fn concurrent_members_agree_and_a_rerun_does_nothing() {
    let Ok(endpoint) = std::env::var("IRON_BOOTSTRAP_LIVE_ENDPOINT") else {
        panic!("set IRON_BOOTSTRAP_LIVE_ENDPOINT");
    };
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let pid = format!("bst{}", nanos % 1_000_000_000);
    let s = settings(&endpoint, &pid);

    // Three members provisioning at once.
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let s = s.clone();
        tasks.push(tokio::spawn(async move {
            let mut store = wait_for_store(&s, Duration::from_millis(200)).await.unwrap();
            provision(&mut store, &s).await.unwrap()
        }));
    }
    let mut reports = Vec::new();
    for t in tasks {
        reports.push(t.await.unwrap());
    }
    let sid = &reports[0].domain_sid;
    assert!(sid.starts_with("S-1-5-21-"), "{sid}");
    assert!(reports.iter().all(|r| &r.domain_sid == sid), "members disagree on the domain SID: {reports:?}");
    let admin = format!("administrator@{}", s.realm);
    let admins = reports.iter().filter(|r| r.created.contains(&admin)).count();
    assert_eq!(admins, 1, "administrator created {admins} times: {reports:?}");

    // The administrator binds by password and has Kerberos keys.
    let mut store = wait_for_store(&s, Duration::from_millis(200)).await.unwrap();
    let entry = store.get_entry(&s.admin_dn().unwrap()).await.unwrap().expect("administrator entry");
    let fips = iron_crypto::FipsContext::new().unwrap();
    let stored = &entry.get("userpassword").unwrap()[0];
    assert!(iron_crypto::pbkdf2::verify_password(&fips, b"TestPass123!", stored).unwrap());
    assert!(!iron_kdc::principal::keys(&entry).unwrap().is_empty());

    // A restart with a different password changes nothing.
    let mut again = s.clone();
    again.admin_password = b"SomethingElse1".to_vec();
    let report = provision(&mut store, &again).await.unwrap();
    assert!(report.created.is_empty(), "{report:?}");
    assert_eq!(&report.domain_sid, sid);
    let after = store.get_entry(&s.admin_dn().unwrap()).await.unwrap().unwrap();
    assert_eq!(after, entry);

    // A different realm for the same partition is refused, not rewritten.
    let mut wrong = s.clone();
    wrong.realm = "OTHER.LO".into();
    assert!(provision(&mut store, &wrong).await.is_err());

    cleanup(&endpoint, &pid).await;
}
