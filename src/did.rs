use libsecp256k1::{util::SignatureArray, Signature};
use std::io::Result;

use crate::keys::KeysStorage;

pub struct Did<T>  where T: KeysStorage {
    platformkeys: T,
    method: String,
    identifier: String,
    fragment: [u8;20],
    path: [u8;20]
}

impl<T: KeysStorage> Did<T> {
    pub fn new() -> Self {
        let platformkeys = T::new();
        match platformkeys.save() {
            Ok(_) => {},
            Err(e) => panic!("failed to save keys : {:?}", e),
        }
        let ethereum_addr = platformkeys.get_keys().generate_ethereum_addr();
        let scurid_identifier = super::keys::encode_eip55_hex(&ethereum_addr);

        Did {
            platformkeys,
            method: String::from("scurid"),
            identifier: scurid_identifier.to_string(),
            fragment: [0u8; 20],
            path: [0u8; 20]
        }
    }

    pub fn from_keys() -> Result<Self> {
        let platformkeys = T::from_saved();
        let ethereum_addr = platformkeys.get_keys().generate_ethereum_addr();
        let scurid_identifier = super::keys::encode_eip55_hex(&ethereum_addr);

        Ok(Did {
            platformkeys,
            method: String::from("scurid"),
            identifier: scurid_identifier.to_string(),
            fragment: [0u8; 20],
            path: [0u8; 20]
        })
    }

    pub fn create_signature(&self, message: &str) -> Result<SignatureArray> {
        let signature = self.platformkeys.get_keys().generate_signature(message)?;

        Ok(signature.serialize_der())
    }

    pub fn verify_signature(&self, message: &str, der_serialized_signature: &[u8]) -> bool {
        let sign = match Signature::parse_der(der_serialized_signature) {
            Ok(s) => s,
            Err(_) => return false
        };
        self.platformkeys.get_keys().verify(message, &sign)
    }

    pub fn get_public_key(&self) -> String {
        let compact_pub_key = self.platformkeys.get_keys().public_key.serialize();
        hex::encode(compact_pub_key)

    }

    pub fn to_string(&self) -> String {
        let mut did = String::from("did:");
        did.push_str(&self.method);
        did.push_str(":");
        did.push_str(&self.identifier);
        did
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use libsecp256k1::Signature;
    use crate::keys::{linuxkeys::LinuxKeys, Keys, KeysStorage};

    #[test]
    fn create_signature() {
        let did = super::Did::<LinuxKeys>::new();
        let message = "test message";
        let ser_signature = match did.create_signature(message) {
            Ok(s) => s,
            Err(_) => panic!("failed to create signature")
        };

        let sig = match Signature::parse_der(&ser_signature.as_ref()) {
            Ok(s) => s,
            Err(_) => panic!("failed to parse signature")
        };

        assert!(did.platformkeys.get_keys().verify(message, &sig));
    }

    #[test]
    fn verify_correct_signature() {
        let did = super::Did::<LinuxKeys>::new();
        let message = "test message";
        let ser_signature = match did.create_signature(message) {
            Ok(s) => s,
            Err(_) => panic!("failed to create signature")
        };
        assert!(did.verify_signature(message, &ser_signature.as_ref()));
    }

    #[test]
    fn verify_altered_signature() {
        let did = super::Did::<LinuxKeys>::new();
        let message = "test message";
        let ser_signature = match did.create_signature(message) {
            Ok(s) => s,
            Err(_) => panic!("failed to create signature")
        };
        assert!(did.verify_signature(message, &ser_signature.as_ref()));
        
        let keys = Keys::new();
        let different_signature = match keys.generate_signature(message) {
            Ok(s) => s,
            Err(_) => panic!("failed to create signature")
        };
        
        assert!(!did.verify_signature(message, &different_signature.serialize_der().as_ref()));
    }

    #[test]
    fn public_key() {
        let did = super::Did::<LinuxKeys>::new();
        let pub_key = did.get_public_key();

        assert_eq!(hex::encode(did.platformkeys.get_keys().public_key.serialize()), pub_key);
    }

    #[test]
    fn did_string() {
        let did = super::Did::<LinuxKeys>::new();
        let did_str = did.to_string();
        println!("{}", did_str);
        let did_split: Vec<&str> = did_str.split(":").collect();
        assert_eq!(did_split.len(), 3);
        assert_eq!(did_split[0], "did");
        assert_eq!(did_split[1], did.method);
        assert_eq!(did_split[2], did.identifier);
    }

    #[test]
    fn create_from_existing() {
        let did = match super::Did::<LinuxKeys>::from_keys() {
            Ok(d) => d,
            Err(e) => panic!("failed to create did from existing keys : {:?}", e)
        };

        let platformkeys = LinuxKeys::from_saved();

        assert_eq!(did.platformkeys.get_keys().public_key.serialize(), platformkeys.get_keys().public_key.serialize());

        let new_did = super::Did::<LinuxKeys>::new();
        assert_ne!(new_did.platformkeys.get_keys().public_key.serialize(), platformkeys.get_keys().public_key.serialize());
    }

    #[test]
    fn create_from_existing_no_files() {
        match fs::remove_file("key") {
            Ok(_) => (),
            Err(_) => println!("failed to remove key file"),
        };
        match fs::remove_file("key.pub") {
            Ok(_) => (),
            Err(_) => println!("failed to remove key.pub file"),
        };

        let did = super::Did::<LinuxKeys>::from_keys();
        assert!(did.is_err());
    }

    #[test]
    fn same_keys_same_did() {
        let did1 = super::Did::<LinuxKeys>::new();
        let did2 = match super::Did::<LinuxKeys>::from_keys() {
            Ok(d) => d,
            Err(e) => panic!("failed to create did from existing keys : {:?}", e)
        };
        assert_eq!(did1.platformkeys.get_keys().public_key.serialize(), did2.platformkeys.get_keys().public_key.serialize());
        assert_eq!(did1.to_string(), did2.to_string());
    }
}