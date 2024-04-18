use std::io::{Result, Error, ErrorKind};
use embedded_svc::wifi::{ClientConfiguration, Configuration};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    nvs::EspDefaultNvsPartition,
    wifi::EspWifi,
    tls::{self, EspTls, X509, InternalSocket},
};
use core::ffi::CStr;

use microscurid_rust::{agent, did};

mod secrets;

fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Welcome!");

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    let mut wifi_driver = EspWifi::new(
        peripherals.modem,
        sys_loop,
        Some(nvs)
    ).unwrap();

    wifi_driver.set_configuration(&Configuration::Client(ClientConfiguration{
        ssid: heapless::String::try_from(secrets::WIFI_SSID).unwrap(),
        password: heapless::String::try_from(secrets::WIFI_PASSWORD).unwrap(),
        ..Default::default()
    })).unwrap();

    wifi_driver.start().unwrap();
    wifi_driver.connect().unwrap();
    while !wifi_driver.is_connected().unwrap(){
        let config = wifi_driver.get_configuration().unwrap();
        println!("Waiting for station {:?}", config);
    }
    println!("Should be connected now");
    
    println!("IP info: {:?}", wifi_driver.sta_netif().get_ip_info().unwrap());

    let did = did::Did::from_keys();
    let agent;
    if did.is_err() {
        agent = agent::Agent::new("rust-agent-esp32s3", "localhost");
    } else {
        agent = agent::Agent::from_did(did.unwrap(), "rust-agent", "localhost");
    }
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

// Reference https://github.com/esp-rs/esp-idf-svc/blob/master/examples/tls.rs
fn send_msg(message: Vec<u8>, hostname: &str, port: u32, expect_response: bool) -> Result<Vec<u8>> {
    let mut tls: EspTls<InternalSocket>;
    match EspTls::new() {
        Ok(r) => tls = r,
        Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
    }

    match tls.connect(
        hostname,
        port as u16,
        &tls::Config {
            common_name: Some(hostname),
            ca_cert: Some(X509::pem(
                CStr::from_bytes_with_nul(secrets::CA_CERT.as_bytes()).unwrap(),
            )),
            ..Default::default()
        },
    ) {
        Ok(_) => (),
        Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
    }

    tls.write_all(message.as_slice()).unwrap();

    if expect_response {
        let mut response = Vec::new();
        tls.read(&mut response).unwrap();
        // stdout().write_all(&response).unwrap();
    
        Ok(response)
    } else {
        Ok(Vec::new())
    }
}