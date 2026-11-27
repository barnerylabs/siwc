//! A cached write while another process replaces the same service's lost key.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use siwc::testing::FakeProvider;
use siwc::{AppName, Client};

use super::renewal::{AfterRefresh, sign_in};
use super::*;

const GUARD: Duration = Duration::from_secs(5);

fn gate_store(dir: &Path) -> File {
    let path = dir.join(format!("pause-store-{ROTATED}"));
    assert!(
        Command::new("/bin/mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn wait_for_store(dir: &Path) {
    let started = dir.join(format!("store-{ROTATED}-started"));
    let until = Instant::now() + GUARD;
    while !started.exists() {
        assert!(
            Instant::now() < until,
            "the gated key replacement did not start"
        );
        thread::yield_now();
    }
}

fn rotating(files: &PrivateFiles) -> Keychain {
    Keychain::new(ROTATED, files)
        .unwrap()
        .with_retired(SERVICE)
        .unwrap()
}

#[test]
fn an_ordinary_write_waits_for_same_service_key_replacement() {
    with_fake_tool(
        "replacement::an_ordinary_write_waits_for_same_service_key_replacement",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let seed = name("seed");
            Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap())
                .write(&seed, VALUE)
                .unwrap();
            let warm = Sealed::new(files.clone(), rotating(&files));
            assert!(warm.read(&seed).unwrap().is_some());
            fs::remove_file(dir.join(ROTATED)).unwrap();
            let mut gate = gate_store(dir);
            let cold_files = files.clone();
            let cold_seed = seed.clone();
            let replacement = thread::spawn(move || {
                Sealed::new(cold_files.clone(), rotating(&cold_files)).read(&cold_seed)
            });
            wait_for_store(dir);
            let entry = name("account-new");
            let write_entry = entry.clone();
            let (done, result) = mpsc::channel();
            let writer = thread::spawn(move || done.send(warm.write(&write_entry, VALUE)).unwrap());
            assert!(result.recv_timeout(Duration::from_millis(100)).is_err());
            gate.write_all(b"\n").unwrap();
            assert!(replacement.join().unwrap().unwrap().is_some());
            result.recv_timeout(GUARD).unwrap().unwrap();
            writer.join().unwrap();
            assert_eq!(
                Sealed::new(files.clone(), rotating(&files))
                    .read(&entry)
                    .unwrap()
                    .unwrap()
                    .expose(),
                VALUE
            );
        },
    );
}

#[test]
fn a_refresh_successor_waits_for_same_service_key_replacement() {
    with_fake_tool(
        "replacement::a_refresh_successor_waits_for_same_service_key_replacement",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let original = Client::new(
                app.clone(),
                Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap()),
                provider.clone(),
            );
            let id = sign_in(&original, &provider);
            let (started, replacement_started) = mpsc::channel();
            let (replacement_done, replacement_result) = mpsc::channel();
            let cold_files = files.clone();
            let gate_dir = dir.to_path_buf();
            let hook = move || {
                thread::spawn(move || {
                    replacement_done
                        .send(
                            Sealed::new(cold_files.clone(), rotating(&cold_files))
                                .read(&name("installation")),
                        )
                        .unwrap();
                });
                wait_for_store(&gate_dir);
                started.send(()).unwrap();
            };
            let transport = AfterRefresh {
                provider: provider.clone(),
                once: Mutex::new(Some(hook)),
            };
            let warm = Client::new(
                app.clone(),
                Sealed::new(files.clone(), rotating(&files)),
                transport,
            );
            let first = warm.access_token(&id).unwrap();
            fs::remove_file(dir.join(ROTATED)).unwrap();
            let mut gate = gate_store(dir);
            let (done, result) = mpsc::channel();
            let renew_id = id.clone();
            let renew = thread::spawn(move || {
                done.send(warm.access_token_after_rejection(&renew_id, &first))
                    .unwrap()
            });
            replacement_started.recv_timeout(GUARD).unwrap();
            assert!(result.recv_timeout(Duration::from_millis(100)).is_err());
            gate.write_all(b"\n").unwrap();
            assert!(
                replacement_result
                    .recv_timeout(GUARD)
                    .unwrap()
                    .unwrap()
                    .is_some()
            );
            let successor = result.recv_timeout(GUARD).unwrap().unwrap();
            renew.join().unwrap();
            let cold_key = rotating(&files);
            let cold = Client::new(app, Sealed::new(files, cold_key), provider);
            assert_eq!(cold.access_token(&id).unwrap().expose(), successor.expose());
            assert!(cold.access_token_after_rejection(&id, &successor).is_ok());
        },
    );
}
