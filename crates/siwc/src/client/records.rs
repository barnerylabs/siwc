//! The installation record: its format and its strict reader.
//!
//! The record names the installation's host ID, a registration whose first
//! sign-in has not completed yet, and the accounts in the order they were
//! added. Each account's credentials live in an entry of their own, written
//! with [`Credentials::to_stored`](crate::protocol::Credentials::to_stored).

use serde_json::{Map, Value};

use crate::account::{Account, AccountId, AccountState};
use crate::app::is_stored_name;
use crate::error::Error;
use crate::host::HostId;
use crate::protocol::{Identity, IssuedClientId, base64url, json};

/// The most accounts one installation holds.
pub(super) const MAX_ACCOUNTS: usize = 32;

/// The longest label, in characters.
const MAX_LABEL_CHARS: usize = 64;

/// The format version this code writes and the only one it reads.
const VERSION: u64 = 1;
const BUNDLE_RECEIPT_LEN: usize = 43;

/// Every member of the record and of each of its parts; each one is always
/// written, absent values as `null`.
const MEMBERS: [&str; 5] = ["v", "host_id", "pending", "selected", "accounts"];
const PENDING_MEMBERS: [&str; 2] = ["client_id", "registered_as"];
const ACCOUNT_MEMBERS: [&str; 10] = [
    "id",
    "client_id",
    "registered_as",
    "label",
    "identity",
    "state",
    "plan_use",
    "welcomed",
    "sign_outs",
    "bundle_receipt",
];

/// Everything the installation entry holds.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Installation {
    pub(super) host: HostId,
    pub(super) pending: Option<Pending>,
    pub(super) selected: Option<AccountId>,
    pub(super) accounts: Vec<AccountRecord>,
}

/// A registration the provider issued whose first sign-in did not complete.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Pending {
    pub(super) client_id: IssuedClientId,
    pub(super) registered_as: String,
}

/// One account as the installation entry holds it.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct AccountRecord {
    pub(super) id: AccountId,
    pub(super) client_id: IssuedClientId,
    pub(super) registered_as: String,
    pub(super) label: Option<String>,
    pub(super) identity: Identity,
    pub(super) state: AccountState,
    pub(super) plan_use: bool,
    /// Whether a sign-in of this account has ever ended with plan use.
    pub(super) welcomed: bool,
    /// How many times [`Client::sign_out`] has completed for this account,
    /// so an in-flight `sign_in_again` notices a sign-out that crossed it.
    pub(super) sign_outs: u64,
    /// SHA-256 of the last bundle whose account metadata was committed.
    pub(super) bundle_receipt: Option<String>,
}

impl Installation {
    /// A new installation with no account yet.
    pub(super) fn new(host: HostId) -> Self {
        Self {
            host,
            pending: None,
            selected: None,
            accounts: Vec::new(),
        }
    }

    /// The account with this ID.
    pub(super) fn account(&self, id: &AccountId) -> Option<&AccountRecord> {
        self.accounts.iter().find(|record| record.id == *id)
    }

    /// The account with this ID, to change it.
    pub(super) fn account_mut(&mut self, id: &AccountId) -> Option<&mut AccountRecord> {
        self.accounts.iter_mut().find(|record| record.id == *id)
    }

    /// Removes `id` from `accounts` and clears `selected` if it named `id`,
    /// preserving [`is_consistent`](Self::is_consistent) across rollbacks and
    /// [`Client::forget`](crate::Client::forget).
    pub(super) fn remove_account(&mut self, id: &AccountId) {
        self.accounts.retain(|record| record.id != *id);
        if self.selected.as_ref() == Some(id) {
            self.selected = None;
        }
    }

    /// What the app sees of one account.
    pub(super) fn snapshot(&self, record: &AccountRecord) -> Account {
        let shares_login_with = self
            .accounts
            .iter()
            .filter(|other| {
                other.id != record.id && other.identity.subject() == record.identity.subject()
            })
            .map(|other| other.id.clone())
            .collect();
        Account {
            id: record.id.clone(),
            label: record.label.clone(),
            identity: record.identity.clone(),
            state: record.state,
            plan_use: record.plan_use,
            registered_as: record.registered_as.clone(),
            shares_login_with,
        }
    }

    /// What the app sees of the account with this ID.
    pub(super) fn snapshot_of(&self, id: &AccountId) -> Option<Account> {
        self.account(id).map(|record| self.snapshot(record))
    }

    /// The entry's bytes.
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut object = Map::new();
        object.insert("v".to_owned(), VERSION.into());
        object.insert("host_id".to_owned(), self.host.as_str().into());
        object.insert(
            "pending".to_owned(),
            self.pending.as_ref().map_or(Value::Null, Pending::to_value),
        );
        object.insert(
            "selected".to_owned(),
            self.selected
                .as_ref()
                .map_or(Value::Null, |id| id.as_str().into()),
        );
        object.insert(
            "accounts".to_owned(),
            Value::Array(self.accounts.iter().map(AccountRecord::to_value).collect()),
        );
        Value::Object(object).to_string().into_bytes()
    }

    /// Reads the entry's bytes. The version has to be [`VERSION`], every
    /// member present with its type and no other member may appear. IDs and
    /// client IDs are unique, and there are at most [`MAX_ACCOUNTS`] accounts.
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let corrupt = || Error::corrupt_entry("the stored installation record cannot be read");
        let object = json::object(bytes).ok_or_else(corrupt)?;
        if object
            .get("v")
            .and_then(Value::as_u64)
            .is_some_and(|v| v != VERSION)
        {
            return Err(Error::unsupported_format());
        }
        Self::parse(&object).ok_or_else(corrupt)
    }

    fn parse(object: &Map<String, Value>) -> Option<Self> {
        if !json::exact(object, &MEMBERS) || object.get("v")?.as_u64()? != VERSION {
            return None;
        }
        let selected = match object.get("selected")? {
            Value::Null => None,
            Value::String(id) => Some(AccountId::parse(id).ok()?),
            _ => return None,
        };
        let host = HostId::parse(object.get("host_id")?.as_str()?).ok()?;
        let pending = match object.get("pending")? {
            Value::Null => None,
            value => Some(Pending::from_value(value)?),
        };
        let entries = object.get("accounts")?.as_array()?;
        if entries.len() > MAX_ACCOUNTS {
            return None;
        }
        let accounts = entries
            .iter()
            .map(AccountRecord::from_value)
            .collect::<Option<Vec<_>>>()?;
        let installation = Self {
            host,
            pending,
            selected,
            accounts,
        };
        installation.is_consistent().then_some(installation)
    }

    /// Whether the record keeps its rules: at most [`MAX_ACCOUNTS`]
    /// accounts, no account ID or client ID twice, `selected` (if set) names a
    /// listed account, and a pending registration is no account's.
    pub(super) fn is_consistent(&self) -> bool {
        self.accounts.len() <= MAX_ACCOUNTS
            && self
                .selected
                .as_ref()
                .is_none_or(|id| self.account(id).is_some())
            && self.accounts.iter().enumerate().all(|(index, record)| {
                let repeated = self
                    .accounts
                    .iter()
                    .skip(index + 1)
                    .any(|other| other.id == record.id || other.client_id == record.client_id);
                let pending_taken = self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.client_id == record.client_id);
                !repeated && !pending_taken
            })
    }
}

impl Pending {
    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("client_id".to_owned(), self.client_id.as_str().into());
        object.insert(
            "registered_as".to_owned(),
            self.registered_as.as_str().into(),
        );
        Value::Object(object)
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if !json::exact(object, &PENDING_MEMBERS) {
            return None;
        }
        Some(Self {
            client_id: IssuedClientId::parse(object.get("client_id")?.as_str()?).ok()?,
            registered_as: app_name(object.get("registered_as")?)?,
        })
    }
}

impl AccountRecord {
    pub(super) fn next_sign_out(&self) -> Result<u64, Error> {
        self.sign_outs
            .checked_add(1)
            .ok_or_else(|| Error::corrupt_entry("the sign-out count is exhausted"))
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("id".to_owned(), self.id.as_str().into());
        object.insert("client_id".to_owned(), self.client_id.as_str().into());
        object.insert(
            "registered_as".to_owned(),
            self.registered_as.as_str().into(),
        );
        object.insert(
            "label".to_owned(),
            self.label.as_deref().map_or(Value::Null, Value::from),
        );
        object.insert("identity".to_owned(), self.identity.to_record());
        object.insert("state".to_owned(), self.state.name().into());
        object.insert("plan_use".to_owned(), self.plan_use.into());
        object.insert("welcomed".to_owned(), self.welcomed.into());
        object.insert("sign_outs".to_owned(), self.sign_outs.into());
        object.insert(
            "bundle_receipt".to_owned(),
            self.bundle_receipt
                .as_deref()
                .map_or(Value::Null, Value::from),
        );
        Value::Object(object)
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if !json::exact(object, &ACCOUNT_MEMBERS) {
            return None;
        }
        let bundle_receipt = match object.get("bundle_receipt")? {
            Value::Null => None,
            Value::String(receipt)
                if receipt.len() == BUNDLE_RECEIPT_LEN
                    && base64url::decode(receipt).is_some_and(|digest| digest.len() == 32) =>
            {
                Some(receipt.clone())
            }
            _ => return None,
        };
        let label = match object.get("label")? {
            Value::Null => None,
            Value::String(text) if is_label(text) => Some(text.clone()),
            _ => return None,
        };
        Some(Self {
            id: AccountId::parse(object.get("id")?.as_str()?).ok()?,
            client_id: IssuedClientId::parse(object.get("client_id")?.as_str()?).ok()?,
            registered_as: app_name(object.get("registered_as")?)?,
            label,
            identity: Identity::from_record(object.get("identity")?)?,
            state: AccountState::from_name(object.get("state")?.as_str()?)?,
            plan_use: object.get("plan_use")?.as_bool()?,
            welcomed: object.get("welcomed")?.as_bool()?,
            sign_outs: object.get("sign_outs")?.as_u64()?,
            bundle_receipt,
        })
    }
}

/// Whether `text` is a label: 1 to 64 characters, none of them a control,
/// invisible or text-direction character.
pub(super) fn is_label(text: &str) -> bool {
    let chars = text.chars().take(MAX_LABEL_CHARS + 1).count();
    (1..=MAX_LABEL_CHARS).contains(&chars) && !crate::app::has_disallowed_chars(text)
}

/// The historical name of a registration, exactly as it was stored.
pub(super) fn app_name(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    is_stored_name(text).then(|| text.to_owned())
}

/// Exercises installation-record parsing for cargo-fuzz harnesses.
#[cfg(fuzzing)]
pub(crate) fn fuzz_installation(data: &[u8]) {
    let _parsed = Installation::from_bytes(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, client_id: &str) -> AccountRecord {
        AccountRecord {
            id: AccountId::parse(id).unwrap(),
            client_id: IssuedClientId::parse(client_id).unwrap(),
            registered_as: "Paste Perfect".to_owned(),
            label: Some("Work".to_owned()),
            identity: Identity::from_record(&serde_json::json!({
                "subject": "user-alex-0001",
                "email": "alex@example.com",
                "email_verified": true,
                "name": null,
                "picture": null,
            }))
            .unwrap(),
            state: AccountState::SignInRequired,
            plan_use: true,
            welcomed: false,
            sign_outs: 0,
            bundle_receipt: None,
        }
    }

    fn installation() -> Installation {
        let host = HostId::parse("urn:uuid:00000000-0000-4000-8000-000000000000").unwrap();
        Installation {
            host,
            pending: Some(Pending {
                client_id: IssuedClientId::parse("app_pending").unwrap(),
                registered_as: "Paste Perfect".to_owned(),
            }),
            selected: None,
            accounts: vec![
                record("00000000000000000000000000000001", "app_one"),
                record("00000000000000000000000000000002", "app_two"),
            ],
        }
    }

    #[test]
    fn selected_account_round_trips_and_must_name_a_listed_account() {
        let mut with_selected = installation();
        let chosen = AccountId::parse("00000000000000000000000000000002").unwrap();
        with_selected.selected = Some(chosen.clone());
        let encoded = with_selected.to_bytes();
        let decoded = Installation::from_bytes(&encoded).unwrap();
        assert!(decoded == with_selected);
        assert_eq!(decoded.to_bytes(), encoded);

        let mut raw: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(raw["v"], 1);
        raw["selected"] = "00000000000000000000000000000099".into();
        assert!(reread(&raw).is_err());

        with_selected.remove_account(&chosen);
        assert_eq!(with_selected.selected, None);
        assert!(with_selected.is_consistent());
        assert!(Installation::from_bytes(&with_selected.to_bytes()).is_ok());
    }

    fn reread(value: &Value) -> Result<Installation, Error> {
        Installation::from_bytes(value.to_string().as_bytes())
    }

    #[test]
    fn a_record_reads_back_what_was_written() {
        let written = installation();
        let read = Installation::from_bytes(&written.to_bytes()).unwrap();
        assert_eq!(read.to_bytes(), written.to_bytes());
        let first = read.accounts.first().unwrap();
        assert_eq!(first.state, AccountState::SignInRequired);
        assert_eq!(first.label.as_deref(), Some("Work"));
        assert_eq!(first.identity.email(), Some("alex@example.com"));
        assert_eq!(read.pending.unwrap().client_id.as_str(), "app_pending");
    }

    #[test]
    fn a_record_distinguishes_an_unsupported_version_from_a_malformed_one() {
        let mut other: Value = serde_json::from_slice(&installation().to_bytes()).unwrap();
        for version in [0.into(), 2.into(), Value::Null, "1".into()] {
            let expected = if version.is_u64() {
                crate::ErrorKind::StoreUnsupported
            } else {
                crate::ErrorKind::StoreCorrupt
            };
            other["v"] = version;
            let error = reread(&other).err().unwrap();
            assert_eq!(error.kind(), expected);
        }
    }

    #[test]
    fn repeated_ids_or_client_ids_are_corrupt() {
        let mut twice = installation();
        twice
            .accounts
            .push(record("00000000000000000000000000000001", "app_three"));
        assert!(Installation::from_bytes(&twice.to_bytes()).is_err());

        let mut shared = installation();
        shared
            .accounts
            .push(record("00000000000000000000000000000003", "app_one"));
        assert!(Installation::from_bytes(&shared.to_bytes()).is_err());

        let mut pending = installation();
        pending
            .accounts
            .push(record("00000000000000000000000000000003", "app_pending"));
        assert!(Installation::from_bytes(&pending.to_bytes()).is_err());
    }

    #[test]
    fn a_missing_unknown_or_mistyped_member_is_corrupt() {
        let good: Value = serde_json::from_slice(&installation().to_bytes()).unwrap();
        assert!(reread(&good).is_ok());
        let edits: [fn(&mut Value); 19] = [
            |value| value["extra"] = true.into(),
            |value| drop(value.as_object_mut().unwrap().remove("pending")),
            |value| drop(value.as_object_mut().unwrap().remove("selected")),
            |value| value["selected"] = 7.into(),
            |value| value["host_id"] = "alex@example.com".into(),
            |value| value["accounts"][0]["state"] = "active".into(),
            |value| value["accounts"][0]["label"] = "".into(),
            |value| value["accounts"][0]["label"] = "tab\there".into(),
            |value| value["accounts"][0]["registered_as"] = " Paste Perfect".into(),
            |value| value["accounts"][0]["identity"]["subject"] = 7.into(),
            |value| {
                drop(
                    value["accounts"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("sign_outs"),
                )
            },
            |value| value["accounts"][0]["sign_outs"] = Value::Null,
            |value| value["accounts"][0]["sign_outs"] = (-1).into(),
            |value| value["accounts"][0]["sign_outs"] = 1.5.into(),
            |value| value["accounts"][0]["sign_outs"] = "0".into(),
            |value| {
                drop(
                    value["accounts"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("bundle_receipt"),
                )
            },
            |value| value["accounts"][0]["bundle_receipt"] = "receipt".into(),
            |value| value["accounts"][0]["bundle_receipt"] = 7.into(),
            |value| value["accounts"][0]["extra"] = true.into(),
        ];
        for (index, edit) in edits.iter().enumerate() {
            let mut value = good.clone();
            edit(&mut value);
            assert!(reread(&value).is_err(), "edit {index}");
        }
    }

    #[test]
    fn more_than_32_accounts_are_corrupt() {
        let mut full = installation();
        full.pending = None;
        full.accounts = (0..=MAX_ACCOUNTS)
            .map(|index| record(&format!("{index:032x}"), &format!("app_{index}")))
            .collect();
        assert!(Installation::from_bytes(&full.to_bytes()).is_err());
        full.accounts.pop();
        assert!(Installation::from_bytes(&full.to_bytes()).is_ok());
    }

    #[test]
    fn labels_are_1_to_64_characters_without_control_characters() {
        assert!(is_label("W"));
        assert!(is_label(&"\u{e4}".repeat(64)));
        assert!(!is_label(&"\u{e4}".repeat(65)));
        assert!(!is_label(""));
        assert!(!is_label("line\nbreak"));
        assert!(!is_label("rtl\u{202E}spoof"));
        assert!(!is_label("zero\u{200B}width"));
    }
}
