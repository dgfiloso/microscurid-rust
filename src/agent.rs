use std::io::Result;
use std::time::SystemTime;

use prost::Message;
use libsecp256k1::util::SignatureArray;

use crate::did::Did;
use crate::keys::KeysStorage;
use crate::microscurid;

const SERVER_PORT: u32 = 8888;

pub struct Agent<T>  where T: KeysStorage {
    did: Did<T>,
    device_name: String,
    hostname: String,
}

impl<T: KeysStorage> Agent<T> {
    pub fn new(device_name: &str, hostname: &str) -> Self {
        let did = super::did::Did::new();
        let name = String::from(device_name);
        let server_hostname = String::from(hostname);
        Agent {
            did,
            device_name: name,
            hostname: server_hostname,
        }
    }

    pub fn from_did(did: Did<T>, device_name: &str, hostname: &str) -> Self {
        let name = String::from(device_name);
        let server_hostname = String::from(hostname);
        Agent {
            did,
            device_name: name,
            hostname: server_hostname,
        }
    }

    pub fn get_did(&self) -> &Did<T> {
        &self.did
    }

    pub fn register_did(&self, send_msg: fn(message: Vec<u8>, hostname: &str, port: u32, expect_response: bool) -> Result<Vec<u8>>) -> Result<()> {
        let register_metadata_message = self.create_register_metadata_message();
        let buf = register_metadata_message.encode_to_vec();

        let res = match send_msg(buf, self.hostname.as_str(), SERVER_PORT, true) {
            Ok(r) => r,
            Err(e) => panic!("failed to send/receive message : {:?}", e),
        };

        let response = match microscurid::v0::RegisterDeviceIdentityRes::decode(res.as_slice()) {
            Ok(r) => r,
            Err(e) => panic!("failed to parse response : {:?}", e),
        };

        if response.result {
            Ok(())
        } else {
            panic!("From server, failed in receiving/decoding the result");
        }
    }

    fn create_register_device_identity(&self) -> microscurid::v0::RegisterDeviceIdentity {
        let mut register_id = microscurid::v0::RegisterDeviceIdentity::default();
        register_id.did = self.did.to_string();
        register_id.unix_time = get_sys_time_in_secs();
        register_id.device_name = self.device_name.clone();
        register_id
    }

    fn create_register_metadata_message(&self) -> microscurid::v0::ReqMetadata {
        let register_id = self.create_register_device_identity();
        let mut register_metadata = microscurid::v0::ReqMetadata::default();
        register_metadata
            .set_req_type(microscurid::v0::req_metadata::ReqType::IdentityRegistration);
        register_metadata.register_device_identity = Some(register_id);
        register_metadata
    }

    pub fn message_verification(&self, message: &str, ser_signature: &SignatureArray, send_msg: fn(message: Vec<u8>, hostname: &str, port: u32, expect_response: bool) -> Result<Vec<u8>>) -> Result<()> {
        let verify_signature_metadata_message = self.create_verify_signature_metadata_message(message, ser_signature);
        let buf = verify_signature_metadata_message.encode_to_vec();

        let _ = send_msg(buf, self.hostname.as_str(), SERVER_PORT, false);

        Ok(())
    }

    fn create_verify_signature(&self, message: &str, ser_signature: &SignatureArray) -> microscurid::v0::VerifySignature {
        let mut verifify_signature = microscurid::v0::VerifySignature::default();
        let mut result_comp_pub_key = String::from("0x");
        let mut result_signature = String::from("0x");
        result_comp_pub_key.push_str(&self.did.get_public_key());
        result_signature.push_str(&hex::encode_upper(ser_signature.as_ref()));
        
        verifify_signature.did = self.did.to_string();
        verifify_signature.compressed_public_key = result_comp_pub_key;
        verifify_signature.signature = result_signature;
        verifify_signature.msg_hash_payload = String::from(message);
        verifify_signature
    }

    fn create_verify_signature_metadata_message(&self, message: &str, ser_signature: &SignatureArray) -> microscurid::v0::ReqMetadata {
        let verify_signature = self.create_verify_signature(message, ser_signature);
        let mut metadata = microscurid::v0::ReqMetadata::default();
        metadata
            .set_req_type(microscurid::v0::req_metadata::ReqType::Verify);
        metadata.verify_signature = Some(verify_signature);
        metadata
    }
}

fn get_sys_time_in_secs() -> i64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs().try_into().unwrap(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::linuxkeys::LinuxKeys;
    
    #[test]
    fn create_from_did() {
        let did = super::Did::<LinuxKeys>::new();
        let did2 = super::Did::<LinuxKeys>::from_keys();
        println!("Did : {}", did2.to_string());
        assert_eq!(did.to_string(), did2.to_string());

        let agent = super::Agent::from_did(did, "rust-agent", "localhost");
        println!("Agent Did : {}", agent.get_did().to_string());
        assert_eq!(agent.get_did().to_string(), did2.to_string());
    }
}