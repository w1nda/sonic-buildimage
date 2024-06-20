extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;

use std::env;

fn mac_to_bytes(mac: &str) -> [u8; 6] {
    let mut bytes = [0u8; 6];
    for (i, byte) in mac.split(':').map(|b| u8::from_str_radix(b, 16).unwrap()).enumerate() {
        bytes[i] = byte;
    }
    bytes
}

fn generate_magic_packet(src_mac: String, dst_mac: String) -> [u8; 116] {
    let mut pkt = [0u8; 116];
    pkt[0..6].copy_from_slice(&mac_to_bytes(&dst_mac));
    pkt[6..12].copy_from_slice(&mac_to_bytes(&src_mac));
    pkt[12..14].copy_from_slice(&[0x08, 0x42]);
    pkt[14..20].copy_from_slice(&[0xff; 6]);
    pkt[20..116].copy_from_slice(&mac_to_bytes(&dst_mac).repeat(16));
    pkt
}

fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let dst_mac = env::args().nth(2).unwrap();
    // Find the network interface with the provided name
    let interface = datalink::interfaces()
                                .into_iter()
                                .filter(|iface: &NetworkInterface| iface.name == interface_name)
                                .next()
                                .expect("Could not find target interface");
    let src_mac = interface.mac.expect("Could not get MAC address of target interface").to_string();

    // Create a new channel for layer 2 transmission
    let mut tx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => tx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    let magic_bytes = generate_magic_packet(src_mac, dst_mac);
    tx.send_to(&magic_bytes, Some(interface));
}