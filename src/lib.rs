/*******************************************************************************
*   (c) 2018, 2019 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
//! Provider for Ledger Tendermint validator app
#[macro_use]
extern crate quick_error;

extern crate byteorder;
extern crate ledger;

const CLA: u8 = 0x56;
const INS_GET_VERSION: u8 = 0x00;
const INS_PUBLIC_KEY_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x02;

const USER_MESSAGE_CHUNK_SIZE: usize = 250;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        InvalidVersion{
            description("This version is not supported")
        }
        InvalidEmptyMessage{
            description("message cannot be empty")
        }
        InvalidMessageSize{
            description("message size is invalid (too big)")
        }
        InvalidPK{
            description("received an invalid PK")
        }
        NoSignature {
            description("received no signature back")
        }
        InvalidSignature {
            description("received an invalid signature")
        }
        InvalidDerivationPath {
            description("invalid derivation path")
        }
        Ledger ( err: ledger::Error ) {
            from()
            description("ledger error")
            display("Ledger error: {}", err)
            cause(err)
        }
    }
}

#[allow(dead_code)]
pub struct TendermintValidatorApp
{
    app: ledger::LedgerApp,
    error_state: bool,
}

unsafe impl Send for TendermintValidatorApp {}

#[allow(dead_code)]
pub struct Version {
    mode: u8,
    major: u8,
    minor: u8,
    patch: u8,
}

impl TendermintValidatorApp {
    pub fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::new()?;
        Ok(TendermintValidatorApp { app, error_state: false })
    }

    pub fn set_logging(&mut self, val: bool) {
        self.app.set_logging(val);
    }

    pub fn version(&self) -> Result<Version, Error> {
        use ledger::ApduCommand;

        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        let response = self.app.exchange(command)?;

        let version = Version {
            mode: response.data[0],
            major: response.data[1],
            minor: response.data[2],
            patch: response.data[3],
        };

        Result::Ok(version)
    }

    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        use ledger::ApduCommand;

        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        if self.app.logging() {
            println!("{:#?}", command);
        }

        let response = self.app.exchange(command)?;

        if self.app.logging() {
            println!("{:#?}", response);
        }

        if response.data.len() != 32 {
            return Err(Error::InvalidPK);
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&response.data[..32]);
        Ok(array)
    }

    // Sign message
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        use ledger::ApduCommand;
        use ledger::ApduAnswer;

        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        if chunks.len() > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if chunks.len() == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let packet_count = chunks.len() as u8;
        let mut response: ApduAnswer = ApduAnswer { data: vec![], retcode: 0 };

        // Send message chunks
        for (packet_idx, chunk) in chunks.enumerate() {
            let _command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_ED25519,
                p1: (packet_idx + 1) as u8,
                p2: packet_count,
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };

            response = self.app.exchange(_command)?;
        }

        if response.data.len() == 0 && response.retcode == 0x9000 {
            return Err(Error::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut array = [0u8; 64];
        array.copy_from_slice(&response.data[..64]);
        Ok(array)
    }
}

#[cfg(test)]
#[macro_use]
extern crate matches;

#[cfg(test)]
extern crate sha2;

#[cfg(test)]
extern crate ed25519_dalek;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use crate::Error;
    use crate::TendermintValidatorApp;
    use std::time::Instant;
    use std::thread;
    use core::time;

    lazy_static! {
        static ref TEST_MUTEX: Mutex<Vec<u8>> = Mutex::new(vec![]);
    }

    fn get_fake_proposal(index: u64, round: i64) -> Vec<u8> {
        use byteorder::{LittleEndian, WriteBytesExt};
        let other: [u8; 12] = [0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1];

        let mut message = Vec::new();
        message.write_u8(0).unwrap();                           // (field_number << 3) | wire_type

        message.write_u8(0x08).unwrap();                        // (field_number << 3) | wire_type
        message.write_u8(0x01).unwrap();                        // PrevoteType

        message.write_u8(0x11).unwrap();                        // (field_number << 3) | wire_type
        message.write_u64::<LittleEndian>(index).unwrap();

        message.write_u8(0x19).unwrap();                        // (field_number << 3) | wire_type
        message.write_i64::<LittleEndian>(round).unwrap();

        // remaining fields (timestamp, not checked):
        message.write_u8(0x22).unwrap();                        // (field_number << 3) | wire_type
        message.extend_from_slice(&other);

        // Increase index
        message[0] = message.len() as u8 - 1;
        message
    }

    #[test]
    fn version() {
        let _test_mutex = TEST_MUTEX.lock().unwrap();
        let app = TendermintValidatorApp::connect().unwrap();

        let resp = app.version();

        match resp {
            Ok(version) => {
                println!("mode  {}", version.mode);
                println!("major {}", version.major);
                println!("minor {}", version.minor);
                println!("patch {}", version.patch);

                assert_eq!(version.mode, 0xFF);
                assert_eq!(version.major, 0x00);
                assert!(version.minor >= 0x04);
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
            }
        }
    }

    #[test]
    fn public_key() {
        let _test_mutex = TEST_MUTEX.lock().unwrap();
        let app = TendermintValidatorApp::connect().unwrap();

        let resp = app.public_key().unwrap();

        assert_eq!(resp.len(), 32);
        println!("PK {:0X?}", resp);
    }

    #[test]
    fn sign_empty() {
        let _test_mutex = TEST_MUTEX.lock().unwrap();
        let app = TendermintValidatorApp::connect().unwrap();

        let some_message0 = b"";

        let signature = app.sign(some_message0);
        assert!(signature.is_err());
        assert!(matches!(signature.err().unwrap(), Error::InvalidEmptyMessage));
    }

    #[test]
    fn sign_verify() {
        let _test_mutex = TEST_MUTEX.lock().unwrap();

        let app = TendermintValidatorApp::connect().unwrap();

        let some_message1 = get_fake_proposal(5, 0);
        app.sign(&some_message1).unwrap();

        let some_message2 = get_fake_proposal(6, 0);

        let sig = app.sign(&some_message2).unwrap();

        use ed25519_dalek::PublicKey;
        use ed25519_dalek::Signature;

        println!("{:#?}", sig.to_vec());

        // First, get public key
        let public_key_bytes = app.public_key().unwrap();
        let public_key = PublicKey::from_bytes(&public_key_bytes).unwrap();
        let signature = Signature::from_bytes(&sig).unwrap();

        // Verify signature
        assert!(public_key.verify(&some_message2, &signature).is_ok());
    }

    #[test]
    fn sign_many() {
        let _test_mutex = TEST_MUTEX.lock().unwrap();
        let app = TendermintValidatorApp::connect().unwrap();

        // First, get public key
        let _resp = app.public_key().unwrap();

        // Now send several votes
        for index in 50u8..254u8 {
            let some_message1 = [
                0x8,                                    // (field_number << 3) | wire_type
                0x1,                                    // PrevoteType
                0x11,                                   // (field_number << 3) | wire_type
                index, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // height
                0x19,                                   // (field_number << 3) | wire_type
                0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // round
                0x22, // (field_number << 3) | wire_type
                // remaining fields (timestamp):
                0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1];

            let sig = app.sign(&some_message1).unwrap();
            println!("{:#?}", sig.to_vec());
        }
    }

    #[test]
    fn quick_benchmark() {
        let _test_mutex = TEST_MUTEX.lock().unwrap();
        let app = TendermintValidatorApp::connect().unwrap();

        // initialize app with a vote
        let msg = get_fake_proposal(0, 100);
        app.sign(&msg).unwrap();

        let start = Instant::now();
        // Now send several votes
        for i in 1u64..20u64 {
            app.sign(&get_fake_proposal(i, 100)).unwrap();
        }
        let duration = start.elapsed();
        println!("Elapsed {:?}", duration);
    }
}
