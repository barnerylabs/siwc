//! A slow retired-key fetch and an unrelated write through one sealed store.

use std::sync::{Mutex, mpsc};
use std::thread;

use super::*;

struct WaitingRetiredKey {
    started: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl SealingKey for WaitingRetiredKey {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        key.fill(2);
        Ok(())
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        self.started.send(()).unwrap();
        self.resume.lock().unwrap().recv().unwrap();
        keys.add(|key| {
            key.fill(1);
            Ok(())
        })
    }
}

#[test]
fn a_warm_write_does_not_wait_for_a_retired_key_lookup() {
    let (old, inner) = sealed_store(1);
    let old_entry = name("account-1");
    let new_entry = name("account-2");
    old.write(&old_entry, VALUE).unwrap();
    let (started, waiting) = mpsc::channel();
    let (resume, gate) = mpsc::channel();
    let store = Sealed::new(
        inner,
        WaitingRetiredKey {
            started,
            resume: Mutex::new(gate),
        },
    );
    store.write(&new_entry, VALUE).unwrap();

    thread::scope(|scope| {
        let read = scope.spawn(|| store.read(&old_entry));
        let guard = Duration::from_secs(3);
        if let Err(error) = waiting.recv_timeout(guard) {
            drop(resume);
            panic!("the reader never asked for a retired key: {error}");
        }
        let (done, finished) = mpsc::channel();
        let (store, new_entry) = (&store, &new_entry);
        scope.spawn(move || {
            done.send(store.write(new_entry, b"renewed session"))
                .unwrap();
        });

        let written_during_lookup = finished.recv_timeout(guard);
        resume.send(()).unwrap();
        assert_eq!(read.join().unwrap().unwrap().unwrap().expose(), VALUE);
        written_during_lookup
            .expect("the warm write waited for an unrelated retired key")
            .unwrap();
    });
}
