use libsecp256k1::util::SignatureArray;
use rustls::{pki_types, ClientConfig, RootCertStore};
use std::fs::File;
use std::io::{BufReader, Read, Result, Write};

use super::{Agent, AgentTrait};
use crate::did::Did;
use crate::keys::linuxkeys::LinuxKeys;
use crate::keys::KeysStorage;

pub struct LinuxAgent<T: KeysStorage> {
    pub agent: Agent<T>,
}

impl<T: KeysStorage> AgentTrait<T> for LinuxAgent<T> {
    fn new(device_name: &str, hostname: &str) -> Self {
        LinuxAgent {
            agent: super::Agent::new(device_name, hostname),
        }
    }

    fn from_did(did: Did<T>, device_name: &str, hostname: &str) -> Self {
        LinuxAgent {
            agent: super::Agent::from_did(did, device_name, hostname),
        }
    }

    fn get_did(&self) -> &Did<T> {
        self.agent.get_did()
    }

    fn register_did(&self, cert: &str) -> Result<()> {
        self.agent
            .register_did(cert, LinuxAgent::<LinuxKeys>::send_msg)
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
            LinuxAgent::<LinuxKeys>::send_msg,
        )
    }

    fn send_msg(
        message: Vec<u8>,
        hostname: &str,
        port: u32,
        cert: &str,
        expect_response: bool,
    ) -> Result<Vec<u8>> {
        // Load certificate
        let mut root_cert_store = RootCertStore::empty();
        let mut pem = BufReader::new(File::open(cert)?);
        for cert in rustls_pemfile::certs(&mut pem) {
            root_cert_store.add(cert?).unwrap();
        }
        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        // Set connection
        let server_name = match pki_types::ServerName::try_from(String::from(hostname)) {
            Ok(s) => s,
            Err(_) => panic!("invalid DNS name"),
        };
        let server = (hostname, port as u16);
        let mut conn =
            rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
        let mut sock = std::net::TcpStream::connect(server).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        tls.write_all(message.as_slice()).unwrap();

        if expect_response {
            let mut response = Vec::new();
            tls.read_to_end(&mut response).unwrap();
            Ok(response)
        } else {
            Ok(Vec::new())
        }
    }
}
