use libsecp256k1::{PublicKey, PublicKeyFormat, SecretKey, Signature};
use super::{Keys, KeysStorage, COMP_PUB_KEY_LEN, ETHEREUM_ADDR_LEN, PRIV_KEY_LEN};
use esp_idf_svc::nvs::*;
use std::io::Result;

const PRIV_KEY_FILE: &str = "key";
const PUB_KEY_FILE: &str = "key.pub";

pub struct EspIdfKeys {
    keys: Keys,
}

impl KeysStorage for EspIdfKeys {
    fn new() -> Self {
        EspIdfKeys {
            keys: super::Keys::new(),
        }
    }

    fn generate_new_keys(&mut self) {
        self.keys.generate_new_keys();
    }

    fn get_public_key(&self) -> PublicKey {
        self.keys.public_key
    }

    fn from_saved() -> Self {
        let nvs_default_partition: EspNvsPartition<NvsDefault> = match EspDefaultNvsPartition::take() {
            Ok(nvs_default_partition) => nvs_default_partition,
            Err(_) => {
                return EspIdfKeys {
                    keys: super::Keys::new(),
                }
            }
        };
        let namespace = "keys_storage";
        let nvs = match EspNvs::new(nvs_default_partition, namespace, true) {
            Ok(nvs) => {
                log::info!("Got namespace {:?} from default partition", namespace);
                nvs
            }
            Err(e) => panic!("Could't get namespace {:?}", e),
        };

        let mut secret_key = [0u8; PRIV_KEY_LEN];
        match nvs.get_raw(PRIV_KEY_FILE, &mut secret_key) {
            Ok(v) => match v {
                Some(vv) => log::info!("{:?} = {:?}", PRIV_KEY_FILE, vv),
                None => todo!(),
            },
            Err(e) => log::info!("Couldn't get key {} because{:?}", PRIV_KEY_FILE, e),
        };
        
        let mut compressed_pub_key = [0u8; COMP_PUB_KEY_LEN];
        match nvs.get_raw(PUB_KEY_FILE, &mut compressed_pub_key) {
            Ok(v) => match v {
                Some(vv) => log::info!("{:?} = {:?}", PUB_KEY_FILE, vv),
                None => todo!(),
            },
            Err(e) => log::info!("Couldn't get key {} because{:?}", PUB_KEY_FILE, e),
        };

        EspIdfKeys {
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
        let nvs_default_partition: EspNvsPartition<NvsDefault> = match EspDefaultNvsPartition::take() {
            Ok(nvs_default_partition) => nvs_default_partition,
            Err(e) => panic!("Could't get nvs default partition {:?}", e),
        };
        let namespace = "keys_storage";
        let mut nvs = match EspNvs::new(nvs_default_partition, namespace, true) {
            Ok(nvs) => {
                log::info!("Got namespace {:?} from default partition", namespace);
                nvs
            }
            Err(e) => panic!("Could't get namespace {:?}", e),
        };

        match nvs.set_raw(PRIV_KEY_FILE, &self.keys.secret_key.serialize()) {
            Ok(_) => log::info!("Private key updated"),
            Err(e) => log::info!("Private key not updated {:?}", e),
        };

        match nvs.set_raw(PUB_KEY_FILE, &self.keys.public_key.serialize_compressed()) {
            Ok(_) => log::info!("Public key updated"),
            Err(e) => log::info!("Public key not updated {:?}", e),
        };

        Ok(())
    }
    fn exist(&self) -> bool {
        let nvs_default_partition: EspNvsPartition<NvsDefault> = match EspDefaultNvsPartition::take() {
            Ok(nvs_default_partition) => nvs_default_partition,
            Err(e) => panic!("Could't get nvs default partition {:?}", e),
        };
        let namespace = "keys_storage";
        let nvs = match EspNvs::new(nvs_default_partition, namespace, true) {
            Ok(nvs) => {
                log::info!("Got namespace {:?} from default partition", namespace);
                nvs
            }
            Err(e) => panic!("Could't get namespace {:?}", e),
        };

        let exist_secret_key = match nvs.contains(PRIV_KEY_FILE) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let exist_public_key = match nvs.contains(PUB_KEY_FILE) {
            Ok(v) => v,
            Err(_) => return false,
        };

        exist_secret_key && exist_public_key
    }

    fn generate_signature(&self, message: &str) -> Result<Signature> {
        self.keys.generate_signature(message)
    }

    fn verify(&self, message: &str, signature: &Signature) -> bool {
        self.keys.verify(message, signature)
    }

    fn generate_ethereum_addr(&self) -> [u8; ETHEREUM_ADDR_LEN] {
        self.keys.generate_ethereum_addr()
    }
}
