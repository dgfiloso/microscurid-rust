# MicroScurid for Rust

## Linux example

### Configuration

Create file `cert.pem` and add the certificate to the same folder as the app binary.

### Run

```bash
$ cd examples/linux
$ cargo run

# Release mode
$ cargo run --release
```

## ESP32S3 example

### Configuration

Create the file `src/secrets.rs` and add the following code, according to your WiFi network and certificate.

```rust
pub const WIFI_SSID : &str = "ssid";
pub const WIFI_PASSWORD : &str = "password";
pub const CA_CERT: &str = "-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----";
```

### Build, flash and monitor ESP32S3 example

Tested with the [Adafruit ESP32-S3 TFT Feather](https://learn.adafruit.com/adafruit-esp32-s3-tft-feather/overview) board.

```bash
$ cd examples/esp32s3
$ cargo build
$ espflash flash --flash-size 4mb --monitor target/xtensa-esp32s3-espidf/debug/microscurid-rust-esp32s3
```