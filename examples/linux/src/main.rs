use std::fs::File;
use std::io::{BufReader, Read, Result, Write};
use rustls::{pki_types, ClientConfig, RootCertStore};

use microscurid_rust::{agent, did, keys::linuxkeys::LinuxKeys};

const CERT_FILE: &str = "ca-cert.pem";

fn main() {
    println!("Welcome!");

    let did = did::Did::<LinuxKeys>::from_keys();
    let agent = agent::Agent::from_did(did, "rust-agent-linux", "localhost");
    
    println!("Agent Did : {}", agent.get_did().to_string());
    println!("Agent Public Key : 0x{}", agent.get_did().get_public_key());

    match agent.register_did(send_msg) {
        Ok(_) => println!("did registered successfully"),
        Err(e) => panic!("failed to send did : {:?}", e),
    }

    let message = "test message";
    let signature = match agent.get_did().create_signature(message) {
        Ok(s) => s,
        Err(e) => panic!("failed to create signature : {:?}", e),
    };
    assert!(agent.get_did().verify_signature(message, &signature.as_ref()));

    match agent.message_verification(message, &signature, send_msg) {
        Ok(_) => println!("message verified successfully"),
        Err(e) => panic!("failed to verify message : {:?}", e),
    }
}

fn send_msg(message: Vec<u8>, hostname: &str, port: u32, expect_response: bool) -> Result<Vec<u8>> {
    // Load certificate
    let mut root_cert_store = RootCertStore::empty();
    let mut pem = BufReader::new(File::open(CERT_FILE)?);
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
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
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