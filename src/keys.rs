use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use secp256k1::ecdsa::Signature;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha3::{Shake256, digest::{Update, ExtendableOutput}};

const PRIV_KEY_LEN: usize = 32;
const COMP_PUB_KEY_LEN: usize = 33;
const HASH_LEN: usize = 32;
const ETHEREUM_ADDR_LEN: usize = 20;
const PRIV_KEY_FILE: &str = "key";
const PUB_KEY_FILE: &str = "key.pub";
// const EIP55_ADDR_LEN: usize = 2 * ETHEREUM_ADDR_LEN;
// const DER_SERIALIZED_SIGNATURE_LEN: usize = 72; // 23 * 3 + 3

pub struct Keys {
    secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Keys {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        Keys {
            secret_key,
            public_key,
        }
    }

    pub fn from_file() -> std::io::Result<Self> {
        let mut file = File::open(PRIV_KEY_FILE)?;
        let mut secret_key = [0u8; PRIV_KEY_LEN];
        file.read(&mut secret_key)?;

        let mut file = File::open(PUB_KEY_FILE)?;
        let mut compressed_pub_key = [0u8; COMP_PUB_KEY_LEN];
        file.read(&mut compressed_pub_key)?;
        
        Ok(Keys{
            secret_key: SecretKey::from_slice(&secret_key).unwrap(),
            public_key: PublicKey::from_slice(&compressed_pub_key).unwrap(),
        })
    }

    pub fn generate_new_keys(&mut self) {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        self.secret_key = secret_key;
        self.public_key = public_key;
    }

    fn hash_message(message: &[u8]) -> [u8; HASH_LEN] {
        let mut hasher = Shake256::default();
        hasher.update(message);
        let mut reader = hasher.finalize_xof();
        let mut hash = [0u8; HASH_LEN];
        match reader.read(&mut hash) {
            Ok(_) => hash,
            Err(_) => panic!("error hashing message : {:?}", message)
        }
    }

    pub fn generate_signature(&self, message: &str) -> Signature {
        let hash = Self::hash_message(message.as_bytes());

        let secp = Secp256k1::new();
        let data = Message::from_digest(hash);
        secp.sign_ecdsa(&data, &self.secret_key)
    }

    pub fn verify(&self, message: &str, signature: &Signature) -> bool {
        let secp = Secp256k1::new();
        let hash = Self::hash_message(message.as_bytes());
        let msg = Message::from_digest(hash);
        match secp.verify_ecdsa(&msg, &signature, &self.public_key) {
            Ok(_) => true,
            Err(_) => false
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let mut file = File::create(PRIV_KEY_FILE)?;
        file.write_all(&self.secret_key.secret_bytes())?;

        let mut file = File::create(PUB_KEY_FILE)?;
        file.write_all(&self.public_key.serialize())?;

        Ok(())
    }

    pub fn keys_exist() -> bool {
        Path::new(PRIV_KEY_FILE).exists() && Path::new(PUB_KEY_FILE).exists()
    }

    pub fn generate_ethereum_addr(&self) -> [u8; ETHEREUM_ADDR_LEN] {
        let mut ethereum_addr = [0u8; ETHEREUM_ADDR_LEN];
        let hash = Self::hash_message(&self.public_key.serialize());
        ethereum_addr[..].clone_from_slice(&hash[(HASH_LEN-ETHEREUM_ADDR_LEN)..]);
        ethereum_addr
    }
}

pub fn encode_eip55_hex(ethereum_addr: &[u8; ETHEREUM_ADDR_LEN]) -> String {
    let eip55_addr = hex::encode_upper(ethereum_addr);
    eip55::checksum(&eip55_addr)
}

#[cfg(test)]
mod tests {
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

    use crate::keys::{ETHEREUM_ADDR_LEN, HASH_LEN};
    
    #[test]
    fn keys_generation() {
        let keys = super::Keys::new();
        println!("secret key {} bytes : 0x{}", keys.secret_key.secret_bytes().len(), hex::encode_upper(keys.secret_key.secret_bytes()));
        println!("compressed public key {} bytes : 0x{}", keys.public_key.serialize().len(), hex::encode_upper(keys.public_key.serialize()));
    }

    #[test]
    fn keys_regeneration() {
        let mut keys = super::Keys::new();
        println!("old secret key {} bytes : 0x{}", keys.secret_key.secret_bytes().len(), hex::encode_upper(keys.secret_key.secret_bytes()));
        println!("old compressed public key {} bytes : 0x{}", keys.public_key.serialize().len(), hex::encode_upper(keys.public_key.serialize()));
        let old_sec_key = keys.secret_key.secret_bytes();
        let old_compressed_pub_key = keys.public_key.serialize();
        
        keys.generate_new_keys();
        println!("new secret key {} bytes : 0x{}", keys.secret_key.secret_bytes().len(), hex::encode_upper(keys.secret_key.secret_bytes()));
        println!("new compressed public key {} bytes : 0x{}", keys.public_key.serialize().len(), hex::encode_upper(keys.public_key.serialize()));

        assert_ne!(keys.secret_key.secret_bytes(), old_sec_key);
        assert_ne!(keys.public_key.serialize(), old_compressed_pub_key);
    }

    #[test]
    fn message_hash() {
        let message = String::from("test message");
        let hash = super::Keys::hash_message(message.as_bytes());
        assert_eq!(hash, hex_literal::hex!("4290667f3eeb1bd8b50b7bdf93cf4dc813212c3005aa7f9b287ddf3f39052350"));
    }

    #[test]
    fn message_signature() {
        let message = "test message";
        let sec_key = SecretKey::from_slice(&hex_literal::hex!("45AE6FE98D538E7781D54BAB8F4F915120198F511D75F6ABDE6CCF06AD3426FC")).unwrap();
        let pub_key = PublicKey::from_slice(&hex_literal::hex!("02325D3959769F1CE9BB81D638F32CCB0BA939EC8AC01A76B0FEF9879AA6FD2D45")).unwrap();
        let keys = super::Keys{
            secret_key: sec_key,
            public_key: pub_key,
        };
        println!("secret key {} bytes : 0x{}", keys.secret_key.secret_bytes().len(), hex::encode_upper(keys.secret_key.secret_bytes()));
        println!("compressed public key {} bytes : 0x{}", keys.public_key.serialize().len(), hex::encode_upper(keys.public_key.serialize()));

        let signature = keys.generate_signature(message);
        println!("serialized signature : 0x{}", hex::encode_upper(signature.serialize_der()));
        assert_eq!(hex::encode_upper(signature.serialize_der()), "304402206D66A0E37D4CC63F46DB6DE91562068730706838C06D33A2744D50513BAA5BA602202CD74250333BE41AC91F938E86163D6FC64F57D58F40018803FE553F4A6BD6AC");

        let secp = Secp256k1::new();
        let message = String::from("test message");
        let hash = super::Keys::hash_message(message.as_bytes());
        let msg = Message::from_digest(hash);
        assert!(secp.verify_ecdsa(&msg, &signature, &pub_key).is_ok());
    }

    #[test]
    fn ethereum_addr() {
        let sec_key = SecretKey::from_slice(&hex_literal::hex!("45AE6FE98D538E7781D54BAB8F4F915120198F511D75F6ABDE6CCF06AD3426FC")).unwrap();
        let pub_key = PublicKey::from_slice(&hex_literal::hex!("02325D3959769F1CE9BB81D638F32CCB0BA939EC8AC01A76B0FEF9879AA6FD2D45")).unwrap();
        let keys = super::Keys{
            secret_key: sec_key,
            public_key: pub_key,
        };
        println!("secret key {} bytes : 0x{}", keys.secret_key.secret_bytes().len(), hex::encode_upper(keys.secret_key.secret_bytes()));
        println!("compressed public key {} bytes : 0x{}", keys.public_key.serialize().len(), hex::encode_upper(keys.public_key.serialize()));

        let hash = super::Keys::hash_message(&keys.public_key.serialize());
        println!("hash compressed public key {} bytes : 0x{}", hash.len(), hex::encode_upper(hash));
        let expected_hash = hex_literal::hex!("0DC0E7BB1BC6B966B3A6A12734AD571F6CA0B90F971A3ACA1509E0DF1D082526");
        assert_eq!(hash, expected_hash);

        let ethereum_addr = keys.generate_ethereum_addr();
        println!("ethereum address {} bytes : 0x{}", ethereum_addr.len(), hex::encode_upper(ethereum_addr));
        assert_eq!(ethereum_addr, expected_hash[(HASH_LEN-ETHEREUM_ADDR_LEN)..]);
    }

    #[test]
    fn eip55_addr() {
        let ethereum_addr = hex_literal::hex!("140bd206e0ecc3e2a6f38b3a1e9faad527886992");
        let eip55_addr = super::encode_eip55_hex(&ethereum_addr);
        println!("eip55 address {} bytes : {}", eip55_addr.len(), eip55_addr);
        assert_eq!(eip55_addr, String::from("0x140BD206E0ecC3e2a6F38B3a1e9faAD527886992"));
    }
}