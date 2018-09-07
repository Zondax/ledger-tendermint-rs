/*******************************************************************************
*   (c) 2018 ZondaX GmbH
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
//! Provider for Ledger cosmos validator app
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate matches;

extern crate byteorder;
extern crate ledger;

const CLA: u8 = 0x56;
const INS_GET_VERSION: u8 = 0x00;
const INS_PUBLIC_KEY_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x04;

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
        Ledger ( err: ledger::Error ) {
            from()
            description("ledger error")
            display("Ledger error: {}", err)
            cause(err)
        }
    }
}

#[allow(dead_code)]
pub struct CosmosValidatorApp
{
    app: ledger::LedgerApp
}

#[allow(dead_code)]
pub struct Version {
    mode: u8,
    major: u8,
    minor: u8,
    patch: u8,
}

fn to_bip32array(path: &Vec<u32>) -> Result<Vec<u8>, Error> {
    use byteorder::{LittleEndian, WriteBytesExt};

    if path.len() > 10 {
        // TODO: return an error
    }

    let mut answer = Vec::new();
    answer.write_u8(path.len() as u8).unwrap();

    for v in path { answer.write_u32::<LittleEndian>(*v).unwrap(); }

    Ok(answer)
}

impl CosmosValidatorApp {
    pub fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::connect()?;
        Ok(CosmosValidatorApp { app })
    }

    pub fn version(&self) -> Result<Version, Error> {
        use ledger::{ApduCommand, LedgerApp};

        let app = LedgerApp::connect()?;

        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        let response = app.exchange(command)?;

        // TODO: this is just temporary, ledger errors should check for 0x9000
        if response.retcode != 0x9000 {
            return Err(Error::InvalidVersion);
        }

        let version = Version {
            mode: response.data[0],
            major: response.data[1],
            minor: response.data[2],
            patch: response.data[3],
        };

        return Result::Ok(version);
    }

    pub fn public_key(&self) -> Result<Vec<u8>, Error> {
        use ledger::{ApduCommand, LedgerApp};

        let app = LedgerApp::connect()?;

        // TODO: Define what to do with the derivation path
        let mut bip32 = vec![44, 60, 0, 0, 0];
        for i in &mut bip32 {
            *i |= 0x80000000;
        }

        let bip32path = to_bip32array(&bip32)?;

        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: bip32path.len() as u8,
            data: bip32path,
        };

        let response = app.exchange(command)?;

        if response.retcode != 0x9000 {
            println!("WARNING: retcode={:X?}", response.retcode);
        }

        Ok(response.data)
    }

    // Sign message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        use ledger::{ApduCommand, LedgerApp};

        let app = LedgerApp::connect()?;

        let mut bip32 = vec![44, 60, 0, 0, 0];
        for i in &mut bip32 {
            *i |= 0x80000000;
        }
        let bip32path = to_bip32array(&bip32)?;

        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        if chunks.len() > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if chunks.len() == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let mut packet_idx = 1u8;
        let packet_count = 1u8 + chunks.len() as u8;

        // Send request + path
        let command = ApduCommand {
            cla: CLA,
            ins: INS_SIGN_ED25519,
            p1: packet_idx,
            p2: packet_count,
            length: bip32path.len() as u8,
            data: bip32path,
        };
        let mut response = app.exchange(command)?;

        // Send message chunks
        for chunk in chunks {
            packet_idx += 1;

            let command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_ED25519,
                p1: packet_idx,
                p2: packet_count,
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };

            response = app.exchange(command)?;
        }

        // Last response should contain the answer
        Ok(response.data)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn derivation_path() {
        use to_bip32array;

        let mut answer = to_bip32array(&vec![1]).unwrap();
        assert_eq!(answer, b"\x01\
                             \x00\x00\x00\x01");

        answer = to_bip32array(&vec![1, 2]).unwrap();
        assert_eq!(answer, b"\x02\
                             \x00\x00\x00\x01\
                             \x00\x00\x00\x02");

        answer = to_bip32array(&vec![1, 2, 12345]).unwrap();
        assert_eq!(answer, b"\x03\
                             \x00\x00\x00\x01\
                             \x00\x00\x00\x02\
                             \x00\x00\x30\x39");

        answer = to_bip32array(&vec![0x44, 0x60, 0, 0, 0]).unwrap();
        assert_eq!(answer, b"\x05\
                             \x00\x00\x00\x44\
                             \x00\x00\x00\x60\
                             \x00\x00\x00\x00\
                             \x00\x00\x00\x00\
                             \x00\x00\x00\x00");

        answer = to_bip32array(&vec![
            0x44 | 0x80000000,
            0x60 | 0x80000000,
            0 | 0x80000000,
            0 | 0x80000000,
            0 | 0x80000000]).unwrap();

        assert_eq!(answer, b"\x05\
                             \x80\x00\x00\x44\
                             \x80\x00\x00\x60\
                             \x80\x00\x00\x00\
                             \x80\x00\x00\x00\
                             \x80\x00\x00\x00");
    }

    #[test]
    fn version() {
        use CosmosValidatorApp;

        let app = CosmosValidatorApp::connect().unwrap();

        let version = app.version().unwrap();

        assert_eq!(version.mode, 0xFF);
        assert_eq!(version.major, 0x00);
        assert_eq!(version.minor, 0x00);
        assert_eq!(version.patch, 0x01);
    }

    #[test]
    fn public_key() {
        use CosmosValidatorApp;

        let app = CosmosValidatorApp::connect().unwrap();

        let pk = app.public_key().unwrap();
        assert_eq!(pk.len(), 32);

        println!("{:?}", pk);
    }

    #[test]
    fn sign_empty() {
        use CosmosValidatorApp;
        use Error;

        let app = CosmosValidatorApp::connect().unwrap();

        let some_message0 = b"";

        let signature = app.sign(some_message0);
        assert!(signature.is_err());
        assert!(matches!(signature.err().unwrap(), Error::InvalidEmptyMessage));
    }

    #[test]
    fn sign() {
        use CosmosValidatorApp;

        let app = CosmosValidatorApp::connect().unwrap();

        let some_message1 = b"{\"height\":1,\"other\":\"Some dummy data\",\"round\":0}";
        let some_message2 = b"{\"height\":2,\"other\":\"Some dummy data\",\"round\":0}";

        let signature = app.sign(some_message1).unwrap();
        println!("{:?}", signature);

        let signature = app.sign(some_message2).unwrap();
        println!("{:?}", signature);
    }
}
