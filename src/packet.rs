use std::net::Ipv4Addr;

pub fn parse_mac(s: &str) -> Result<[u8;6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("MAC must have 6 octets, got {}", s));
    }
    let mut mac = [0u8;6];
    for (i,p) in parts.iter().enumerate() {
        let v = u8::from_str_radix(p, 16).map_err(|e| format!("invalid mac octet {}: {}", p, e))?;
        mac[i] = v;
    }
    Ok(mac)
}

pub fn build_ethernet(dst_mac: [u8;6], src_mac: [u8;6], ethertype: u16) -> [u8;14] {
    let mut h = [0u8;14];
    h[..6].copy_from_slice(&dst_mac);
    h[6..12].copy_from_slice(&src_mac);
    h[12..14].copy_from_slice(&ethertype.to_be_bytes());
    h
}

pub fn build_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload_len: usize, ip_bitfield: u8, protocol: u8, ttl: u8) -> [u8;20] {
    let total_len = (20 + payload_len) as u16;
    let mut h = [0u8;20];
    h[0] = (4 << 4) | 5;
    h[1] = 0;
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[4..6].copy_from_slice(&0u16.to_be_bytes());
    h[6] = ip_bitfield;
    h[7] = 0;
    h[8] = ttl;
    h[9] = protocol;
    h[12..16].copy_from_slice(&src_ip.octets());
    h[16..20].copy_from_slice(&dst_ip.octets());

    let checksum = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&checksum.to_be_bytes());
    h
}

pub fn ipv4_checksum(header: &[u8;20]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        if i == 10 { continue; }
        let word = u16::from_be_bytes([header[i], header[i+1]]) as u32;
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_udp(src_port: u16, dst_port: u16, payload: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&udp_len.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(payload);

    let checksum = udp_checksum(&buf, src_ip, dst_ip);
    buf[6..8].copy_from_slice(&checksum.to_be_bytes());
    buf
}

pub fn udp_checksum(udp_pkt: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
    let mut sum: u32 = 0;
    // pseudo header
    for b in src_ip.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([b[0], b[1]]) as u32);
    }
    for b in dst_ip.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([b[0], b[1]]) as u32);
    }
    sum = sum.wrapping_add(17u32);
    sum = sum.wrapping_add((udp_pkt.len() as u16) as u32);

    // udp header + data
    let mut i = 0;
    while i + 1 < udp_pkt.len() {
        let w = u16::from_be_bytes([udp_pkt[i], udp_pkt[i+1]]) as u32;
        sum = sum.wrapping_add(w);
        i += 2;
    }
    if i < udp_pkt.len() {
        let last = (udp_pkt[i] as u32) << 8;
        sum = sum.wrapping_add(last);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let s = !(sum as u16);
    if s == 0 { 0xffff } else { s }
}

pub fn build_tcp(src_port: u16, dst_port: u16, payload: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + payload.len());
    
    // TCP header (20 bytes minimum)
    buf.extend_from_slice(&src_port.to_be_bytes());    // Source port (0-1)
    buf.extend_from_slice(&dst_port.to_be_bytes());    // Destination port (2-3)
    buf.extend_from_slice(&0u32.to_be_bytes());        // Sequence number (4-7)
    buf.extend_from_slice(&0u32.to_be_bytes());        // Acknowledgment number (8-11)
    buf.extend_from_slice(&0x5000u16.to_be_bytes());   // Data offset (4 bits) + Reserved (4 bits) + Flags (8 bits) (12-13)
    buf.extend_from_slice(&0xffffu16.to_be_bytes());   // Window size (14-15)
    buf.extend_from_slice(&0u16.to_be_bytes());        // Checksum (16-17) - will be filled later
    buf.extend_from_slice(&0u16.to_be_bytes());        // Urgent pointer (18-19)
    buf.extend_from_slice(payload);                    // Payload

    let checksum = tcp_checksum(&buf, src_ip, dst_ip);
    buf[16..18].copy_from_slice(&checksum.to_be_bytes());
    buf
}

pub fn tcp_checksum(tcp_pkt: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
    let mut sum: u32 = 0;
    
    // TCP pseudo-header
    for b in src_ip.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([b[0], b[1]]) as u32);
    }
    for b in dst_ip.octets().chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([b[0], b[1]]) as u32);
    }
    sum = sum.wrapping_add(6u32);  // TCP protocol number
    sum = sum.wrapping_add((tcp_pkt.len() as u16) as u32);

    // TCP header + data
    let mut i = 0;
    while i + 1 < tcp_pkt.len() {
        let w = u16::from_be_bytes([tcp_pkt[i], tcp_pkt[i+1]]) as u32;
        sum = sum.wrapping_add(w);
        i += 2;
    }
    if i < tcp_pkt.len() {
        let last = (tcp_pkt[i] as u32) << 8;
        sum = sum.wrapping_add(last);
    }
    
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let s = !(sum as u16);
    if s == 0 { 0xffff } else { s }
}
