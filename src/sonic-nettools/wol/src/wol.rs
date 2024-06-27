use clap::Parser;
use pnet::datalink::{self, DataLinkSender, MacAddr, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use std::str::FromStr;

const BROADCAST_MAC: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

pub fn wol(){
    let args = WolArgs::parse();
    let target_macs = parse_target_macs(&args);
    if !is_operstate_up(&args.interface) {
        panic!("Error: The target interface is not up");
    }
    let src_mac = get_interface_mac(&args.interface);
    let mut tx = open_tx_channel(&args.interface);

    for dst_mac in target_macs{
        println!("Building and sending packet to mac address {}", dst_mac.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":"));
        let magic_bytes = build_magic_packet(&src_mac, &dst_mac, &args.password);
        send_magic_packet(&mut tx, magic_bytes, &args.count, &args.interval, &args.verbose);
    }
}

fn parse_mac_addr(mac_str: &str) -> [u8; 6] {
    MacAddr::from_str(mac_str).expect("Invalid MAC address").octets()
}

fn parse_ipv4_addr(ipv4_str: &str) -> [u8; 4] {
    let octets: Vec<u8> = ipv4_str.split('.')
        .map(|octet| octet.parse().expect("Invalid IPv4 address")).collect();
    [octets[0], octets[1], octets[2], octets[3]]
}

fn parse_password(password: &str) -> Result<Password, String> {
    if is_ipv4_address_valid(password) {
        Ok(Password(parse_ipv4_addr(password).to_vec()))
    } else if is_mac_string_valid(password){
        Ok(Password(parse_mac_addr(password).to_vec()))
    } else {
        Err("Invalid password".to_string())
    }
}

fn parse_target_mac(target_mac: &str) -> Vec<[u8; 6]> {

    target_mac.split(',').map(|mac_str| {
        if mac_str == "broadcast" {
            BROADCAST_MAC
        } else {
            parse_mac_addr(mac_str)
        }
    }).collect()
}

fn is_operstate_up(interface: &str) -> bool {
    let state_file_path = format!("/sys/class/net/{}/operstate", interface);
    match std::fs::read_to_string(state_file_path) {
        Ok(content) => content.trim() == "up",
        Err(_) => {
            panic!("Error: Could not read operstate file for interface {}", interface);
        }
    }
}

fn is_mac_string_valid(mac_str: &str) -> bool {
    let mac_str = mac_str.replace(":", "");
    mac_str.len() == 12 && mac_str.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_ipv4_address_valid(ipv4_str: &str) -> bool {
    ipv4_str.split('.').count() == 4 && ipv4_str.split('.').all(|octet| {
        octet.parse::<u64>().map_or(false, |n| n < 256)
    })
}

fn build_magic_packet(src_mac: &[u8; 6], dst_mac: &[u8; 6], password: &Option<Password>) -> Vec<u8> {
    let password_len = password.as_ref().map_or(0, |p| p.ref_bytes().len());
    let mut pkt = vec![0u8; 116 + password_len];
    pkt[0..6].copy_from_slice(dst_mac);
    pkt[6..12].copy_from_slice(src_mac);
    pkt[12..14].copy_from_slice(&[0x08, 0x42]);
    pkt[14..20].copy_from_slice(&[0xff; 6]);
    pkt[20..116].copy_from_slice(&dst_mac.repeat(16));
    if let Some(p) = password {
        pkt[116..116 + password_len].copy_from_slice(p.ref_bytes());
    }
    pkt
}

fn open_tx_channel(interface: &str) -> Box<dyn DataLinkSender> {
    // Find the network interface with the provided name
    let interface = datalink::interfaces()
    .into_iter()
    .find(|iface: &NetworkInterface| iface.name == interface)
    .expect("Could not find target interface");

    // Create a new channel for layer 2 transmission
    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _)) => tx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    }
}

fn send_magic_packet(tx: &mut Box<dyn DataLinkSender>, packet: Vec<u8>, count: &u8, interval: &u64, verbose: &bool) {
    for nth in 0..*count {
        if let Err(e) = tx.send_to(&packet, None).unwrap() {
            eprintln!("Failed to send magic packet: {}", e);
            break;
        }
        if *verbose {
            println!("  | -> Sent the {}th packet and sleep for {} seconds", nth + 1, interval);
            println!("    | -> Packet bytes in hex {}", packet.iter().map(|b| format!("{:02x}", b)).collect::<String>())
        }
        std::thread::sleep(std::time::Duration::from_millis(*interval));
    }
}

#[derive(Parser, Debug)]
#[command(
    next_line_help = true,
    about = "
This tool can generate and send wake on LAN magic packets with target interface and mac

Examples:
    wol Ethernet10 00:11:22:33:44:55
    wol Ethernet10 00:11:22:33:44:55 -b
    wol Vlan1000 00:11:22:33:44:55,11:33:55:77:99:bb -p 00:22:44:66:88:aa
    wol Vlan1000 00:11:22:33:44:55,11:33:55:77:99:bb -p 192.168.1.1 -c 3 -i 2000",
)]
struct WolArgs {

    /// The name of the network interface to send the magic packet through
    #[arg(short, long)]
    interface: String,

    /// The MAC address of the target device, formatted as a colon-separated string (e.g. "00:11:22:33:44:55")
    #[arg(short = 'm', long)]
    target_mac: Option<String>,

    /// The flag to indicate if we use the broadcast MAC address ff:ff:ff:ff:ff:ff as the target MAC address [default: false]
    #[arg(short, long, default_value_t = false)]
    broadcast: bool,

    /// An optional 4 or 6 byte password, in ethernet hex format or quad-dotted decimal (e.g. "127.0.0.1" or "00:11:22:33:44:55")
    #[arg(short, long, value_parser = parse_password)]
    password: Option<Password>,

    /// The number of times to send the magic packet [default: 1][range: 1-5]
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..6))]
    count: u8,

    /// The interval in milliseconds between each magic packet transmission [default: 0][range: 0-2000]
    #[arg(short = 't', long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..2001))]
    interval: u64,

    /// The flag to indicate if we should print verbose output
    #[arg(short, long)]
    verbose: bool
}

#[derive(Debug, Clone)]
struct Password(Vec<u8>);

impl Password {
    fn ref_bytes(&self) -> &Vec<u8> {
        &self.0
    }
}

fn get_interface_mac(interface_name: &String) -> [u8; 6]{
    let interface = datalink::interfaces()
    .into_iter()
    .find(|iface: &NetworkInterface| iface.name == *interface_name)
    .expect("Could not find target interface");
    let mac = interface.mac.expect("Could not get MAC address of target interface").octets();

    mac
}

fn parse_target_macs(args: &WolArgs) -> Vec<[u8; 6]> {
    if args.broadcast && args.target_mac.is_some() {
        panic!("Error: Cannot specify both --broadcast and --target-mac");
    }
    if !args.broadcast && args.target_mac.is_none() {
        panic!("Error: Must specify either --broadcast or --target-mac");
    }

    if args.broadcast {
        vec![BROADCAST_MAC]
    } else {
        parse_target_mac(args.target_mac.as_ref().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_build_magic_packet() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let magic_packet = build_magic_packet(&src_mac, &dst_mac, &None);
        assert_eq!(magic_packet.len(), 116);
        assert_eq!(&magic_packet[0..6], &dst_mac);
        assert_eq!(&magic_packet[6..12], &src_mac);
        assert_eq!(&magic_packet[12..14], &[0x08, 0x42]);
        assert_eq!(&magic_packet[14..20], &[0xff; 6]);
        assert_eq!(&magic_packet[20..116], dst_mac.repeat(16));
    }

    #[test]
    fn verify_cli() {
        WolArgs::command().debug_assert();
    }

    #[test]
    fn verify_cli_with_password() {
        WolArgs::parse_from(vec!["wol", "-i", "Ethernet10", "-m", "00:11:22:33:44:55", "-p", "1.1.1.1"]);
    }
}