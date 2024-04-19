// use std::io::{Result, Error, ErrorKind};
use core::convert::TryInto;
use embedded_svc::wifi::{AuthMethod, ClientConfiguration, Configuration};
use esp_idf_hal::peripherals::Peripherals;

use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use esp_idf_svc::{eventloop::EspSystemEventLoop, nvs::EspDefaultNvsPartition};

use microscurid_rust::{agent::espidfagent::EspIdfAgent, did::Did, keys::espidfkeys::EspIdfKeys};
use microscurid_rust::agent::AgentTrait;

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

    let did = Did::<EspIdfKeys>::from_keys();
    let agent = EspIdfAgent::<EspIdfKeys>::from_did(did, "rust-agent-esp32s3", secrets::SCURID_SERVER);
    println!("Agent Did : {}", agent.get_did().to_string());
    println!("Agent Public Key : 0x{}", agent.get_did().get_public_key());

    match agent.register_did(secrets::CA_CERT) {
        Ok(_) => println!("did registered successfully"),
        Err(e) => panic!("failed to send did : {:?}", e),
    }

    let message = "test message";
    let signature = match agent.get_did().create_signature(message) {
        Ok(s) => s,
        Err(e) => panic!("failed to create signature : {:?}", e),
    };
    assert!(agent.get_did().verify_signature(message, &signature.as_ref()));

    match agent.message_verification(message, &signature, secrets::CA_CERT) {
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