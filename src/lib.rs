pub mod keys;
pub mod did;
pub mod agent;
mod net;

// Include `microscurid` module, which is generated from items.proto.
pub mod microscurid {
    pub mod v0 {
        include!(concat!(env!("OUT_DIR"), "/microscurid.v0.rs"));
    }
}