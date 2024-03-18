extern crate microscurid_rust;

use microscurid_rust::{agent, did};

#[tokio::main]
async fn main() {
    println!("Welcome!");

    let did = did::Did::from_keys();
    let agent;
    if did.is_err() {
        agent = agent::Agent::new("rust-agent", "localhost");
    } else {
        agent = agent::Agent::from_did(did.unwrap(), "rust-agent", "localhost");
    }
    println!("Agent Did : {}", agent.get_did().to_string());
    println!("Agent Public Key : 0x{}", agent.get_did().get_public_key());

    match agent.register_did().await {
        Ok(_) => println!("did registered successfully"),
        Err(e) => panic!("failed to send did : {:?}", e),
    }

    let message = "test message";
    let signature = agent.get_did().create_signature(message);
    assert!(agent.get_did().verify_signature(message, &signature));

    match agent.message_verification(message, &signature).await {
        Ok(_) => println!("message verified successfully"),
        Err(e) => panic!("failed to verify message : {:?}", e),
    }
}