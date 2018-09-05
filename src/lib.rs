//! Provider for Ledger cosmos validator app
#[macro_use]
extern crate quick_error;
extern crate ledger;

const CLA: u8 = 0x56;
const INS_GET_VERSION: u8 = 0x00;
const INS_PUBLIC_KEY_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x04;

quick_error! {
    #[derive(Debug)]
    pub enum LedgerError {
        InvalidVersion{
            description("This version is not supported")
        }
        DeviceNotFound{
            description("Could not find a ledger device")
        }
        // TODO: Improve error handling
//        Comm(additional_description: String) {
//            description("Communication Error: {}", additional_description)
//        }
//        Unknown(additional_description: String) {
//            description("Unknown Error: {}", additional_description)
//        }
    }
}

pub struct LedgerCosmosValidator();

impl LedgerCosmosValidator {
    // TODO: Pass optional derivation path?
//    /// Create a new signer
//    pub fn connect() -> Result<Self, LedgerError> {
//        match SecretKey::from_slice(&SECP256K1_ENGINE, bytes) {
//            Ok(sk) => Ok(EcdsaSigner(sk)),
//            Err(e) => fail!(KeyInvalid, e),
//        }
//    }

    pub fn version() -> Result<u32, LedgerError> {
        use ledger::{ApduCommand, exchange};

        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        match exchange(command)
            {
                Ok(x) => println!("{:?}", x),
                // TODO: Improve error handling
                Err(x) => println!("{:?}", x)
            }
        Ok(1u32)
    }

    pub fn public_key() -> Result<u32, LedgerError> {
        use ledger::{ApduCommand, exchange};

        let bip32path = vec![
            0, 0, 0, 1,
            0, 0, 0, 1];

        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: bip32path.len() as u8,
            data: Vec::new(),
        };

        match exchange(command)
            {
                Ok(x) => println!("{:?}", x),
                // TODO: Improve error handling
                Err(x) => println!("{:?}", x)
            }
        Ok(1u32)
    }

    // Sign message
    // TODO: fix signature, etc.
    pub fn sign() -> Result<u32, LedgerError> {
        use ledger::{ApduCommand, exchange};

        let bip32path = vec![
            0, 0, 0, 1,
            0, 0, 0, 1];

        let command = ApduCommand {
            cla: CLA,
            ins: INS_SIGN_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: bip32path.len() as u8,
            data: Vec::new(),
        };

        match exchange(command)
            {
                Ok(x) => println!("{:?}", x),
                // TODO: Improve error handling
                Err(x) => println!("{:?}", x)
            }
        Ok(1u32)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn version() {
        use LedgerCosmosValidator;

        match LedgerCosmosValidator::version()
            {
                Ok(x) => println!("{:?}", x),
                Err(x) => println!("{:?}", x)
            }
    }

    #[test]
    fn public_key() {
        use LedgerCosmosValidator;

        match LedgerCosmosValidator::public_key()
            {
                Ok(x) => println!("{:?}", x),
                Err(x) => println!("{:?}", x)
            }
    }

    #[test]
    fn sign() {
        use LedgerCosmosValidator;

        match LedgerCosmosValidator::sign()
            {
                Ok(x) => println!("{:?}", x),
                Err(x) => println!("{:?}", x)
            }
    }
}
