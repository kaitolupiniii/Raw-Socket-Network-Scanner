use clap::Parser;
use std::fs::File;
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

mod packet;
use packet::*;

use serde::Serialize;
use pcap_file::pcap::{PcapWriter, PcapHeader, PcapPacket};
use pcap_file::DataLink;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long = "src_ip")] src_ip: Option<Ipv4Addr>,
    #[arg(long = "dst_ip")] dst_ip: Option<Ipv4Addr>,
    #[arg(long = "dest_port")] dest_port: Option<u16>,
    #[arg(long = "src_mac")] src_mac: Option<String>,
    #[arg(long = "dst_mac")] dst_mac: Option<String>,
    #[arg(long = "l4_protocol")] l4_protocol: Option<String>,
    #[arg(long = "timeout_ms", default_value_t = 1000)] timeout_ms: u64,
    #[arg(long = "debug_file")] debug_file: Option<PathBuf>,
    #[arg(long = "debug_format")] debug_format: Option<String>,
    #[arg(long = "ip_bitfield", default_value_t = String::from("0x00"))] ip_bitfield: String,
    #[arg(long = "dry_run", default_value_t = false)] dry_run: bool,
}

#[derive(Serialize)]
struct JsonPacket {
    ethernet: Vec<u8>,
    ipv4: Vec<u8>,
    udp: Option<Vec<u8>>,
    tcp: Option<Vec<u8>>,
    full_packet: Vec<u8>,
    details: PacketDetails,
}

#[derive(Serialize)]
struct PacketDetails {
    constructed_src_ip: String,
    constructed_dst_ip: String,
    src_mac: String,
    dst_mac: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    ip_checksum: u16,
    transport_checksum: u16,
    packet_size: usize,
    ip_bitfield: u8,
}

/// Send UDP packet using standard sockets
fn send_udp_packet(dst_ip: Ipv4Addr, dst_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::UdpSocket;
    
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_ttl(64)?;
    
    let payload = b"RAW_SCANNER_TEST_PACKET";
    match socket.send_to(payload, (dst_ip, dst_port)) {
        Ok(_bytes_sent) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}

/// Send TCP packet using standard sockets
fn send_tcp_packet(dst_ip: Ipv4Addr, dst_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpStream;
    
    // Try to establish a TCP connection (SYN packet)
    match TcpStream::connect_timeout(&(dst_ip, dst_port).into(), Duration::from_millis(1000)) {
        Ok(_stream) => {
            // Connection successful - immediately close it
            // This sends SYN -> SYN-ACK -> ACK -> FIN
            Ok(())
        }
        Err(e) => {
            // Even if connection fails, a SYN packet was sent
            // This is normal for scanning - we don't care if the port is closed
            Ok(())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Validate debug_file and debug_format combination
    if args.debug_file.is_some() && args.debug_format.is_none() {
        eprintln!("Error: --debug_format is required when --debug_file is provided");
        std::process::exit(1);
    }
    
    if let Some(ref format) = args.debug_format {
        if format != "json" && format != "pcap" {
            eprintln!("Error: Invalid debug format '{}'. Must be 'json' or 'pcap'", format);
            std::process::exit(1);
        }
    }

    // Use provided values or defaults
    let src_ip = args.src_ip.unwrap_or(Ipv4Addr::new(192, 168, 1, 100));
    let dst_ip = args.dst_ip.unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    let payload: Vec<u8> = Vec::new();
    
    let protocol = args.l4_protocol.unwrap_or("udp".into());
    let src_mac = parse_mac(args.src_mac.as_deref().unwrap_or("00:00:00:00:00:00"))?;
    let dst_mac = parse_mac(args.dst_mac.as_deref().unwrap_or("ff:ff:ff:ff:ff:ff"))?;
    
    let ip_bitfield = if args.ip_bitfield.starts_with("0x") {
        u8::from_str_radix(&args.ip_bitfield[2..], 16)
            .map_err(|e| format!("Invalid IP bitfield format '{}': {}", args.ip_bitfield, e))?
    } else {
        args.ip_bitfield.parse::<u8>()
            .map_err(|e| format!("Invalid IP bitfield format '{}': {}", args.ip_bitfield, e))?
    };
    
    let dest_port = args.dest_port.unwrap_or(8080);

    // Build packet based on protocol
    let (l4_bytes, protocol_num, transport_checksum, protocol_name) = match protocol.to_lowercase().as_str() {
        "udp" => {
            let udp_packet = build_udp(40000, dest_port, &payload, src_ip, dst_ip);
            let checksum = u16::from_be_bytes([udp_packet[6], udp_packet[7]]);
            (udp_packet, 17, checksum, "udp".to_string())
        }
        "tcp" => {
            let tcp_packet = build_tcp(40000, dest_port, &payload, src_ip, dst_ip);
            let checksum = u16::from_be_bytes([tcp_packet[16], tcp_packet[17]]);
            (tcp_packet, 6, checksum, "tcp".to_string())
        }
        _ => {
            eprintln!("Unsupported protocol: {}. Only 'udp' and 'tcp' are supported", protocol);
            std::process::exit(1);
        }
    };

    // Build IP header with the specified bitfield
    let ip_header = build_ipv4(src_ip, dst_ip, l4_bytes.len(), ip_bitfield, protocol_num, 64);
    let ip_checksum = u16::from_be_bytes([ip_header[10], ip_header[11]]);
    
    // Build Ethernet frame
    let eth = build_ethernet(dst_mac, src_mac, 0x0800);
    
    // Construct full packet
    let mut full_packet: Vec<u8> = Vec::new();
    full_packet.extend_from_slice(&eth);
    full_packet.extend_from_slice(&ip_header);
    full_packet.extend_from_slice(&l4_bytes);

    // Debug output - save constructed packet
    if let (Some(debug_file), Some(fmt)) = (&args.debug_file, args.debug_format.as_deref()) {
        if fmt == "json" {
            let details = PacketDetails {
                constructed_src_ip: src_ip.to_string(),
                constructed_dst_ip: dst_ip.to_string(),
                src_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]),
                dst_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                                dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]),
                src_port: 40000,
                dst_port: dest_port,
                protocol: protocol_name.clone(),
                ip_checksum,
                transport_checksum,
                packet_size: full_packet.len(),
                ip_bitfield,
            };
            
            let jp = match protocol_name.as_str() {
                "udp" => JsonPacket {
                    ethernet: eth.to_vec(),
                    ipv4: ip_header.to_vec(),
                    udp: Some(l4_bytes.clone()),
                    tcp: None,
                    full_packet: full_packet.clone(),
                    details,
                },
                "tcp" => JsonPacket {
                    ethernet: eth.to_vec(),
                    ipv4: ip_header.to_vec(),
                    udp: None,
                    tcp: Some(l4_bytes.clone()),
                    full_packet: full_packet.clone(),
                    details,
                },
                _ => unreachable!(),
            };
            
            let f = File::create(debug_file)?;
            let mut w = BufWriter::new(f);
            serde_json::to_writer(&mut w, &jp)?;
        } else if fmt == "pcap" {
            let f = File::create(debug_file)?;
            let header = PcapHeader {
                datalink: DataLink::ETHERNET,
                ..Default::default()
            };
            let mut writer = PcapWriter::with_header(f, header)?;
            
            let pcap_packet = PcapPacket::new(
                std::time::Duration::ZERO,
                full_packet.len() as u32,
                &full_packet,
            );
            writer.write_packet(&pcap_packet)?;
        }
    }

    // Packet transmission (only if not dry_run)
    if !args.dry_run {
        match protocol_name.as_str() {
            "udp" => {
                if let Err(e) = send_udp_packet(dst_ip, dest_port) {
                    eprintln!("UDP packet transmission failed: {}", e);
                }
            }
            "tcp" => {
                if let Err(e) = send_tcp_packet(dst_ip, dest_port) {
                    eprintln!("TCP packet transmission failed: {}", e);
                }
            }
            _ => unreachable!(),
        }
        
        // Honor the timeout
        std::thread::sleep(Duration::from_millis(args.timeout_ms));
    } else {
        // In dry_run mode, we still need to honor the timeout
        std::thread::sleep(Duration::from_millis(args.timeout_ms));
    }

    Ok(())
}
