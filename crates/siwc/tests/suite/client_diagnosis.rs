//! `Client::diagnose`: a snapshot for a support request that names
//! accounts by ID and holds nothing personal or secret.

use serde_json::Value;
use siwc::AccountId;

use crate::support::NOW;
use crate::support::provider::User;
use crate::support::rig::Rig;

/// The first lines of every diagnosis, up to its clock.
fn head(clock: u64) -> String {
    format!(
        "siwc {} on {} {}\n\
         store shared across processes: yes\n\
         clock: {clock} (Unix seconds)\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

/// The lines of one account in a diagnosis.
fn account_lines(diagnosis: &str, id: &AccountId) -> Vec<String> {
    diagnosis
        .lines()
        .skip_while(|line| *line != format!("account {id}"))
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_diagnosis_reports_each_accounts_state_credentials_token_time_and_lock() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    let kim = rig.add(&User::kim());
    let team = rig.add(&User::alex());
    let alex_entry = rig.credentials_of(alex.id()).unwrap();
    rig.store.put(&format!("account-{}", sam.id()), &alex_entry);
    let _ = rig.client.sign_out(kim.id()).unwrap();
    rig.store
        .put(&format!("account-{}", team.id()), b"not json");
    rig.store.fail_locks_of(&format!("account-{}", alex.id()));
    rig.at(600);

    let text = rig.client.diagnose().to_string();
    let expected = format!(
        "{}\
         installation: 4 account(s), unfinished registration: no\n\
         account {}\n\
         \x20 state: signed_in, plan use: yes\n\
         \x20 credentials: present, client ID and subject match\n\
         \x20 access token: valid for 50 more minute(s), renewable\n\
         \x20 refresh lock: held by another thread or process\n\
         account {}\n\
         \x20 state: signed_in, plan use: yes\n\
         \x20 credentials: another account's (client ID matches: no, subject matches: no)\n\
         \x20 refresh lock: free\n\
         account {}\n\
         \x20 state: signed_out, plan use: yes\n\
         \x20 credentials: missing\n\
         \x20 refresh lock: free\n\
         account {}\n\
         \x20 state: signed_in, plan use: yes\n\
         \x20 credentials: unreadable (store_corrupt)\n\
         \x20 refresh lock: free\n",
        head(NOW + 600),
        alex.id(),
        sam.id(),
        kim.id(),
        team.id(),
    );
    assert_eq!(text, expected);

    rig.at(3600 - 30);
    let due = rig.client.diagnose().to_string();
    assert_eq!(
        account_lines(&due, alex.id())[2],
        "  access token: due for renewal, expires in 0 minute(s), renewable"
    );
    rig.at(3600 + 3 * 60 + 59);
    let expired = rig.client.diagnose().to_string();
    assert_eq!(
        account_lines(&expired, alex.id())[2],
        "  access token: expired 3 minute(s) ago, renewable"
    );
}

#[test]
fn a_store_that_cannot_be_read_is_reported_in_the_diagnosis_and_no_error() {
    let rig = Rig::new();
    let empty = rig.client.diagnose().to_string();
    assert_eq!(empty, format!("{}installation: none yet\n", head(NOW)));

    rig.add(&User::alex());
    rig.store.put("installation", b"not json");
    let broken = rig.client.diagnose().to_string();
    assert_eq!(
        broken,
        format!("{}installation: unreadable (store_corrupt)\n", head(NOW))
    );
}

#[test]
fn diagnosing_sends_nothing_writes_nothing_and_keeps_the_lock_rules() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.add(&User::sam());
    // Due, so a call that renewed would send.
    rig.at(3600 - 30);
    rig.journal.clear();

    let _ = rig.client.diagnose();

    assert!(rig.journal.about("send").is_empty());
    assert!(rig.journal.about("write").is_empty());
    assert!(rig.journal.about("remove").is_empty());
    assert!(
        rig.journal
            .events()
            .contains(&format!("lock account-{}", alex.id())),
        "the lock was tried"
    );
    rig.journal.assert_lock_rules();
}

#[test]
fn a_diagnosis_shows_no_token_client_id_subject_address_name_label_host_id_or_link() {
    let rig = Rig::new();
    let users = [User::alex(), User::sam()];
    let labels = ["Alex at work", "Sam at home"];
    let mut secrets: Vec<String> = Vec::new();
    for (user, label) in users.iter().zip(labels) {
        let account = rig.add(user);
        rig.client.set_label(account.id(), Some(label)).unwrap();
        secrets.push(rig.token(account.id()));
        let stored: Value =
            serde_json::from_slice(&rig.credentials_of(account.id()).unwrap()).unwrap();
        for member in ["refresh_token", "id_token", "client_id"] {
            secrets.push(stored[member].as_str().unwrap().to_owned());
        }
        secrets.extend(
            [user.subject, user.email.unwrap(), user.name.unwrap(), label].map(str::to_owned),
        );
    }
    let installation: Value =
        serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
    secrets.push(installation["host_id"].as_str().unwrap().to_owned());
    // A sign-in waits for the browser while the diagnosis is taken.
    let waiting = rig.client.add_account().unwrap();
    let link = waiting.start_link().to_owned();
    secrets.push(link.rsplit('/').next().unwrap().to_owned());
    secrets.push(link);

    let diagnosis = rig.client.diagnose();
    let printed = format!("{diagnosis:?}\n{diagnosis}");

    for secret in &secrets {
        assert!(secret.len() >= 9, "{secret} is too short to search for");
        assert!(!printed.contains(secret), "{secret} appears in {printed}");
    }
    assert!(!printed.contains("eyJ"), "a JWT appears in {printed}");
    assert_eq!(printed.matches("account ").count(), 2, "{printed}");
}
