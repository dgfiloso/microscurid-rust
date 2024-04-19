// use std::io::{Result, Error, ErrorKind};
use core::convert::TryInto;
use embedded_svc::wifi::{AuthMethod, ClientConfiguration, Configuration};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_svc::tls::{self, EspTls, X509};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use esp_idf_svc::{eventloop::EspSystemEventLoop, nvs::EspDefaultNvsPartition};
use core::ffi::CStr;

use microscurid_rust::{agent, did, keys::esp32s3keys::Esp32s3Keys};

mod secrets;

fn main() -> anyhow::Result<()> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Welcome!");

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;

    connect_wifi(&mut wifi)?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;

    log::info!("Wifi DHCP info: {:?}", ip_info);

    let did = did::Did::<Esp32s3Keys>::from_keys();
    let agent = agent::Agent::from_did(did, "rust-agent-esp32s3", secrets::SCURID_SERVER);
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
        Ok(_) => log::info!("message verified successfully"),
        Err(e) => panic!("failed to verify message : {:?}", e),
    }

    Ok(())
}

// Reference https://github.com/esp-rs/esp-idf-svc/blob/master/examples/wifi.rs
fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: secrets::WIFI_SSID.try_into().unwrap(),
        bssid: None,
        auth_method: AuthMethod::WPA2Personal,
        password: secrets::WIFI_PASSWORD.try_into().unwrap(),
        channel: None,
        ..Default::default()
    });

    wifi.set_configuration(&wifi_configuration)?;

    wifi.start()?;
    log::info!("Wifi started");

    wifi.connect()?;
    log::info!("Wifi connected");

    wifi.wait_netif_up()?;
    log::info!("Wifi netif up");

    Ok(())
}

// Reference https://github.com/esp-rs/esp-idf-svc/blob/master/examples/tls.rs
fn send_msg(message: Vec<u8>, hostname: &str, port: u32, expect_response: bool) -> std::io::Result<Vec<u8>> {
    let mut tls = match EspTls::new() {
        Ok(tls) => tls,
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
    };

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
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
    }

    tls.write_all(message.as_slice()).unwrap();

    if expect_response {
        let mut response = [0; 512];
        let read_size = match tls.read(&mut response) {
            Ok(r) => r,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        };
        
        Ok(response[0..read_size].to_vec())
    } else {
        Ok(Vec::new())
    }
}