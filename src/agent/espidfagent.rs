use libsecp256k1::util::SignatureArray;
use esp_idf_svc::tls::{self, EspTls, X509};
use core::ffi::CStr;
use std::io::Result;

use super::{Agent, AgentTrait};
use crate::did::Did;
use crate::keys::espidfkeys::EspIdfKeys;
use crate::keys::KeysStorage;

pub struct EspIdfAgent<T: KeysStorage> {
    pub agent: Agent<T>,
}

impl<T: KeysStorage> AgentTrait<T> for EspIdfAgent<T> {
    fn new(device_name: &str, hostname: &str) -> Self {
        EspIdfAgent {
            agent: super::Agent::new(device_name, hostname),
        }
    }

    fn from_did(did: Did<T>, device_name: &str, hostname: &str) -> Self {
        EspIdfAgent {
            agent: super::Agent::from_did(did, device_name, hostname),
        }
    }

    fn get_did(&self) -> &Did<T> {
        self.agent.get_did()
    }

    fn register_did(&self, cert: &str) -> Result<()> {
        self.agent
            .register_did(cert, EspIdfAgent::<EspIdfKeys>::send_msg)
    }

    fn message_verification(
        &self,
        message: &str,
        ser_signature: &SignatureArray,
        cert: &str,
    ) -> Result<()> {
        self.agent.message_verification(
            message,
            ser_signature,
            cert,
            EspIdfAgent::<EspIdfKeys>::send_msg,
        )
    }

    // Reference https://github.com/esp-rs/esp-idf-svc/blob/master/examples/tls.rs
    fn send_msg(
        message: Vec<u8>,
        hostname: &str,
        port: u32,
        cert: &str,
        expect_response: bool,
    ) -> std::io::Result<Vec<u8>> {
        let mut tls = match EspTls::new() {
            Ok(tls) => tls,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            }
        };

        match tls.connect(
            hostname,
            port as u16,
            &tls::Config {
                common_name: Some(hostname),
                ca_cert: Some(X509::pem(
                    CStr::from_bytes_with_nul(cert.as_bytes()).unwrap(),
                )),
                ..Default::default()
            },
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            }
        }

        tls.write_all(message.as_slice()).unwrap();

        if expect_response {
            let mut response = [0; 512];
            let read_size = match tls.read(&mut response) {
                Ok(r) => r,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ))
                }
            };

            Ok(response[0..read_size].to_vec())
        } else {
            Ok(Vec::new())
        }
    }
}
