use libsecp256k1::{PublicKey, PublicKeyFormat, SecretKey};

use super::{Keys, KeysStorage, COMP_PUB_KEY_LEN, PRIV_KEY_LEN};

use std::fs::File;
use std::io::{Read, Result, Write};
use std::path::Path;

const PRIV_KEY_FILE: &str = "key";
const PUB_KEY_FILE: &str = "key.pub";

pub struct LinuxKeys {
    keys: Keys,
}

impl KeysStorage for LinuxKeys {
    fn new() -> Self {
        LinuxKeys {
            keys: super::Keys::new(),
        }
    }

    fn get_keys(&self) -> Keys {
        self.keys
    }

    fn from_saved() -> Self {
        let mut file = match File::open(PRIV_KEY_FILE) {
            Ok(f) => f,
            Err(_) => {
                return LinuxKeys {
                    keys: super::Keys::new(),
                }
            }
        };
        let mut secret_key = [0u8; PRIV_KEY_LEN];
        match file.read(&mut secret_key) {
            Ok(_) => (),
            Err(_) => {
                return LinuxKeys {
                    keys: super::Keys::new(),
                }
            }
        };

        let mut file = match File::open(PUB_KEY_FILE) {
            Ok(f) => f,
            Err(_) => {
                return LinuxKeys {
                    keys: super::Keys::new(),
            }}
        };
        let mut compressed_pub_key = [0u8; COMP_PUB_KEY_LEN];
        match file.read(&mut compressed_pub_key) {
            Ok(_) => (),
            Err(_) => {
                return LinuxKeys {
                    keys: super::Keys::new(),
            }}
        };

        LinuxKeys {
            keys: Keys {
                secret_key: SecretKey::parse_slice(&secret_key).unwrap(),
                public_key: PublicKey::parse_slice(
                    &compressed_pub_key,
                    Some(PublicKeyFormat::Compressed),
                )
                .unwrap(),
            },
        }
    }

    fn save(&self) -> Result<()> {
        let mut file = File::create(PRIV_KEY_FILE)?;
        file.write_all(&self.keys.secret_key.serialize())?;

        let mut file = File::create(PUB_KEY_FILE)?;
        file.write_all(&self.keys.public_key.serialize_compressed())?;

        Ok(())
    }

    fn exist(&self) -> bool {
        Path::new(PRIV_KEY_FILE).exists() && Path::new(PUB_KEY_FILE).exists()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::keys::{linuxkeys::{PRIV_KEY_FILE, PUB_KEY_FILE}, KeysStorage};

    #[test]
    fn keys_generation() {
        let platformkeys = super::LinuxKeys::new();
        println!("secret key {} bytes : 0x{}", platformkeys.get_keys().secret_key.serialize().len(), hex::encode_upper(platformkeys.get_keys().secret_key.serialize()));
        println!("compressed public key {} bytes : 0x{}", platformkeys.get_keys().public_key.serialize_compressed().len(), hex::encode_upper(platformkeys.get_keys().public_key.serialize_compressed()));
    }

    #[test]
    fn return_keys() {
        let platformkeys = super::LinuxKeys::new();
        assert_eq!(platformkeys.get_keys().secret_key.serialize().len(), platformkeys.keys.secret_key.serialize().len());
        assert_eq!(platformkeys.get_keys().public_key.serialize_compressed().len(), platformkeys.keys.public_key.serialize_compressed().len());
    }

    #[test]
    fn keys_exist() {
        match fs::remove_file(PRIV_KEY_FILE) {
            Ok(_) => (),
            Err(_) => println!("failed to remove {} file", PRIV_KEY_FILE),
        };
        match fs::remove_file(PUB_KEY_FILE) {
            Ok(_) => (),
            Err(_) => println!("failed to remove {} file", PUB_KEY_FILE),
        };
        
        let platformkeys = super::LinuxKeys::new();
        assert!(!platformkeys.exist());
        let result = platformkeys.save();
        assert!(result.is_ok());
        assert!(platformkeys.exist());
    }

    #[test]
    fn save_keys() {
        let platformkeys = super::LinuxKeys::new();
        let result = platformkeys.save();
        assert!(result.is_ok());
        assert!(platformkeys.exist());
    }

    #[test]
    fn load_keys() {
        let platformkeys1 = super::LinuxKeys::new();
        let result = platformkeys1.save();
        assert!(result.is_ok());

        let platformkeys2 = super::LinuxKeys::from_saved();
        assert_eq!(platformkeys1.get_keys().secret_key.serialize(), platformkeys2.get_keys().secret_key.serialize());
        assert_eq!(platformkeys1.get_keys().public_key.serialize_compressed(), platformkeys2.get_keys().public_key.serialize_compressed());
    }
}
