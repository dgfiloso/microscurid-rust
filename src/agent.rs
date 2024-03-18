use std::io::Result;
use std::time::SystemTime;

use prost::Message;
use secp256k1::ecdsa::SerializedSignature;

use crate::did::Did;
use crate::microscurid;
use crate::net;

const SERVER_PORT: u32 = 8888;

pub struct Agent {
    did: Did,
    device_name: String,
    hostname: String,
}

impl Agent {
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

    pub fn from_did(did: Did, device_name: &str, hostname: &str) -> Self {
        let name = String::from(device_name);
        let server_hostname = String::from(hostname);
        Agent {
            did,
            device_name: name,
            hostname: server_hostname,
        }
    }

    pub fn get_did(&self) -> &Did {
        &self.did
    }

    pub async fn register_did(&self) -> Result<()> {
        let register_metadata_message = self.create_register_metadata_message();
        let buf = register_metadata_message.encode_to_vec();

        let res = match net::send_msg(buf, self.hostname.as_str(), SERVER_PORT, true).await {
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

    pub async fn message_verification(&self, message: &str, ser_signature: &SerializedSignature) -> Result<()> {
        let verify_signature_metadata_message = self.create_verify_signature_metadata_message(message, ser_signature);
        let buf = verify_signature_metadata_message.encode_to_vec();

        net::send_msg(buf, self.hostname.as_str(), SERVER_PORT, false).await?;

        Ok(())
    }

    fn create_verify_signature(&self, message: &str, ser_signature: &SerializedSignature) -> microscurid::v0::VerifySignature {
        let mut verifify_signature = microscurid::v0::VerifySignature::default();
        let mut result_comp_pub_key = String::from("0x");
        let mut result_signature = String::from("0x");
        result_comp_pub_key.push_str(&self.did.get_public_key());
        result_signature.push_str(&hex::encode_upper(ser_signature));
        
        verifify_signature.did = self.did.to_string();
        verifify_signature.compressed_public_key = result_comp_pub_key;
        verifify_signature.signature = result_signature;
        verifify_signature.msg_hash_payload = String::from(message);
        verifify_signature
    }

    fn create_verify_signature_metadata_message(&self, message: &str, ser_signature: &SerializedSignature) -> microscurid::v0::ReqMetadata {
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
    #[tokio::test]
    async fn send_did() {
        let agent = super::Agent::new("rust-agent", "localhost");
        println!("Agent Did : {}", agent.get_did().to_string());
        match agent.register_did().await {
            Ok(_) => println!("did sent successfully"),
            Err(e) => panic!("failed to send did : {:?}", e),
        }
    }

    #[test]
    fn create_from_did() {
        let did = super::Did::new();
        let did2 = match super::Did::from_keys() {
            Ok(d) => d,
            Err(e) => panic!("failed to create did from existing keys : {:?}", e)
        };
        println!("Did : {}", did2.to_string());
        assert_eq!(did.to_string(), did2.to_string());

        let agent = super::Agent::from_did(did, "rust-agent", "localhost");
        println!("Agent Did : {}", agent.get_did().to_string());
        assert_eq!(agent.get_did().to_string(), did2.to_string());
    }
}