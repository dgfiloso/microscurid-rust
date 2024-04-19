use microscurid_rust::{agent::AgentTrait, agent::linuxagent::LinuxAgent, did::Did, keys::linuxkeys::LinuxKeys};

const CERT_FILE: &str = "ca-cert.pem";

fn main() {
    println!("Welcome!");

    let did = Did::<LinuxKeys>::from_keys();
    let agent = LinuxAgent::<LinuxKeys>::from_did(did, "rust-agent-linux", "localhost");
    
    println!("Agent Did : {}", agent.get_did().to_string());
    println!("Agent Public Key : 0x{}", agent.get_did().get_public_key());

    match agent.register_did(CERT_FILE) {
        Ok(_) => println!("did registered successfully"),
        Err(e) => panic!("failed to send did : {:?}", e),
    }

    let message = "test message";
    let signature = match agent.get_did().create_signature(message) {
        Ok(s) => s,
        Err(e) => panic!("failed to create signature : {:?}", e),
    };
    assert!(agent.get_did().verify_signature(message, &signature.as_ref()));

    match agent.message_verification(message, &signature, CERT_FILE) {
        Ok(_) => println!("message verified successfully"),
        Err(e) => panic!("failed to verify message : {:?}", e),
    }
}