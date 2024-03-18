use std::fs::File;
use std::io::{BufReader, Read, Result, Write};
use tokio_rustls::rustls::{self, pki_types, ClientConfig, RootCertStore};

const CERT_FILE: &str = "cert.pem";

// Reference for connecting to server in local network using IP address
// https://users.rust-lang.org/t/rustls-connecting-without-certificate-in-local-network/83822/4

pub async fn send_msg(message: Vec<u8>, hostname: &str, port: u32, expect_response: bool) -> Result<Vec<u8>> {
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
        // stdout().write_all(&response).unwrap();
    
        Ok(response)
    } else {
        Ok(Vec::new())
    }
}