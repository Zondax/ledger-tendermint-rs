extern crate ledger;

const CLA: u8 = 0x56;
const INS_GET_VERSION: u8 = 0x00;
const INS_PUBLIC_KEY_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x04;

#[cfg(test)]
mod tests {
    #[test]
    fn get_version() {
        use CLA;
        use INS_GET_VERSION;
        use INS_PUBLIC_KEY_ED25519;

        use ledger::{ApduCommand, exchange};

        let command = ApduCommand { cla: CLA, ins: INS_GET_VERSION, p1: 0x00, p2: 0x00, length: 0, data: Vec::new() };
        let result = exchange(command);
        match result
            {
                Ok(x) => println!("{:?}", x),
                Err(x) => println!("{:?}", x)
            }

        let mut data = vec![0, 0, 0, 1, 0, 0, 0, 1];

        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: data.len() as u8,
            data: Vec::new(),
        };

        let result = exchange(command);
        match result
            {
                Ok(x) => println!("{:?}", x),
                Err(x) => println!("{:?}", x)
            }
    }

    #[test]
    fn get_public_key() {
        use CLA;
        use INS_GET_VERSION;
        use INS_PUBLIC_KEY_ED25519;

        use ledger::{ApduCommand, exchange};

        let mut bip32path = vec![0, 0, 0, 1, 0, 0, 0, 1];

        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: bip32path.len() as u8,
            data: Vec::new(),
        };

        let result = exchange(command);
        match result
            {
                Ok(x) => println!("{:?}", x),
                Err(x) => println!("{:?}", x)
            }
    }
}
