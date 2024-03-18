use secp256k1::ecdsa::{SerializedSignature, Signature};
use std::io::Result;

pub struct Did {
    keys: super::keys::Keys,
    method: String,
    identifier: String,
    fragment: [u8;20],
    path: [u8;20]
}

impl Did {
    pub fn new() -> Self {
        let keys = super::keys::Keys::new();
        match keys.save() {
            Ok(_) => {},
            Err(e) => panic!("failed to save keys : {:?}", e),
        }
        let ethereum_addr = keys.generate_ethereum_addr();
        let scurid_identifier = super::keys::encode_eip55_hex(&ethereum_addr);

        Did {
            keys,
            method: String::from("scurid"),
            identifier: scurid_identifier.to_string(),
            fragment: [0u8; 20],
            path: [0u8; 20]
        }
    }

    pub fn from_keys() -> Result<Self> {
        let keys = match super::keys::Keys::from_file() {
            Ok(k) => k,
            Err(e) => return Err(e)
        };
        let ethereum_addr = keys.generate_ethereum_addr();
        let scurid_identifier = super::keys::encode_eip55_hex(&ethereum_addr);

        Ok(Did {
            keys,
            method: String::from("scurid"),
            identifier: scurid_identifier.to_string(),
            fragment: [0u8; 20],
            path: [0u8; 20]
        })
    }

    pub fn create_signature(&self, message: &str) -> SerializedSignature {
        let signature = self.keys.generate_signature(message);

        signature.serialize_der()
    }

    pub fn verify_signature(&self, message: &str, der_serialized_signature: &[u8]) -> bool {
        let sign = match Signature::from_der(der_serialized_signature) {
            Ok(s) => s,
            Err(_) => return false
        };
        self.keys.verify(message, &sign)
    }

    pub fn get_public_key(&self) -> String {
        let compact_pub_key = self.keys.public_key.serialize();
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

    use secp256k1::ecdsa::Signature;
    use crate::keys::Keys;

    #[test]
    fn create_signature() {
        let did = super::Did::new();
        let message = "test message";
        let ser_signature = did.create_signature(message);

        let sig = match Signature::from_der(&ser_signature) {
            Ok(s) => s,
            Err(_) => panic!("failed to parse signature")
        };

        assert!(did.keys.verify(message, &sig));
    }

    #[test]
    fn verify_correct_signature() {
        let did = super::Did::new();
        let message = "test message";
        let ser_signature = did.create_signature(message);
        assert!(did.verify_signature(message, &ser_signature));
    }

    #[test]
    fn verify_altered_signature() {
        let did = super::Did::new();
        let message = "test message";
        let ser_signature = did.create_signature(message);
        assert!(did.verify_signature(message, &ser_signature));
        
        let keys = Keys::new();
        let different_signature = keys.generate_signature(message);
        
        assert!(!did.verify_signature(message, &different_signature.serialize_der()));
    }

    #[test]
    fn public_key() {
        let did = super::Did::new();
        let pub_key = did.get_public_key();

        assert_eq!(hex::encode(did.keys.public_key.serialize()), pub_key);
    }

    #[test]
    fn did_string() {
        let did = super::Did::new();
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
        let did = match super::Did::from_keys() {
            Ok(d) => d,
            Err(e) => panic!("failed to create did from existing keys : {:?}", e)
        };

        let keys = match Keys::from_file() {
            Ok(k) => k,
            Err(e) => panic!("failed to load keys : {:?}", e)
        };

        assert_eq!(did.keys.public_key.serialize(), keys.public_key.serialize());

        let new_did = super::Did::new();
        assert_ne!(new_did.keys.public_key.serialize(), keys.public_key.serialize());
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

        let did = super::Did::from_keys();
        assert!(did.is_err());
    }

    #[test]
    fn same_keys_same_did() {
        let did1 = super::Did::new();
        let did2 = match super::Did::from_keys() {
            Ok(d) => d,
            Err(e) => panic!("failed to create did from existing keys : {:?}", e)
        };
        assert_eq!(did1.keys.public_key.serialize(), did2.keys.public_key.serialize());
        assert_eq!(did1.to_string(), did2.to_string());
    }
}