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
use std::sync::{Arc, Mutex};

use signatory::{
    ed25519::{PublicKey, Signature},
    signature::{Signer, Error},
    public_key::PublicKeyed,
};
use crate::ledgertm::TendermintValidatorApp;

/// ed25519 signature provider for the Ledger Tendermint Validator app
pub struct Ed25519LedgerTmAppSigner {
    app: Arc<Mutex<TendermintValidatorApp>>,
}

impl Ed25519LedgerTmAppSigner {
    /// Create a new Ed25519 signer based on Ledger Nano S - Tendermint Validator app
    pub fn connect() -> Result<Self, Error> {
        match TendermintValidatorApp::connect() {
            Ok(validator_app) => {
                let app = Arc::new(Mutex::new(validator_app));
                let signer = Ed25519LedgerTmAppSigner { app };

                // FIXME: Confirm minimum version
                let _pk = signer.public_key()?;
                Ok(signer)
            }
            Err(err) => Err(Error::from_source(err)),
        }
    }
}

impl PublicKeyed<PublicKey> for Ed25519LedgerTmAppSigner {
    /// Returns the public key that corresponds to the Tendermint Validator app connected to this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let app = self.app.lock().unwrap();

        match app.public_key() {
            Ok(pk) => Ok(PublicKey(pk)),
            Err(err) => Err(Error::from_source(err)),
        }
    }
}

impl Signer<Signature> for Ed25519LedgerTmAppSigner {
    /// c: Compute a compact, fixed-sized signature of the given amino/json vote
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let app = self.app.lock().unwrap();

        match app.sign(&msg) {
            Ok(sig) => Ok(Signature(sig)),
            Err(err) => Err(Error::from_source(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::signer::Ed25519LedgerTmAppSigner;
    use signatory::signature::Signer;

    #[test]
    fn public_key() {
        use signatory::public_key::PublicKeyed;
        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        let _pk = signer.public_key().unwrap();
        println!("PK {:0X?}", _pk);
    }

    #[test]
    fn sign() {
        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Sign message1
        let some_message1 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x10, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message1);
    }

    #[test]
    fn sign2() {
        use signatory::signature::Signer;

        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Sign message1
        let some_message1 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message1);

        // Sign message2
        let some_message2 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x10, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message2);
    }

    #[test]
    fn sign_many() {
        use signatory::public_key::PublicKeyed;
        use signatory::signature::Signer;
        use Ed25519LedgerTmAppSigner;

        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Get public key to initialize
        let _pk = signer.public_key().unwrap();
        println!("PK {:0X?}", _pk);

        for index in 50u8..254u8 {
            // Sign message1
            let some_message = [
                33, 0x8,  // (field_number << 3) | wire_type
                0x1,  // PrevoteType
                0x11, // (field_number << 3) | wire_type
                0x40, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
                0x19, // (field_number << 3) | wire_type
                index, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
                0x22, // (field_number << 3) | wire_type
                // remaining fields (timestamp):
                0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
            ];

            signer.sign(&some_message);
        }
    }
}
