#[macro_use]
extern crate lazy_static;

use ledger_tendermint::TendermintValidatorApp;
use std::thread;
use std::time;
use std::sync::Mutex;

lazy_static! {
    static ref TEST_MUTEX: Mutex<Vec<u8>> = Mutex::new(vec![]);
}

#[test]
fn public_key_manual_reconnect() {
    // This test requires unplugging and replugging the app

    let _test_mutex = TEST_MUTEX.lock().unwrap();

    for _i in 1u64..5000u64 {
        if let Ok(app) = TendermintValidatorApp::connect() {
            match app.public_key() {
                Ok(pk) => println!("PK {:0X?}", pk),
                Err(_e) => println!("Err")
            }
        }
        thread::sleep(time::Duration::from_millis(100));
    }
}
