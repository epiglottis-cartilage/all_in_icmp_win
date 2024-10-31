use std::thread;
use windivert::prelude::{WinDivert, WinDivertFlags};
use windivert_sys::ChecksumFlags;

const PROTO_ICMP: u8 = 0x1;
const PROTO_TCP: u8 = 0x6;
const PROTO_UDP: u8 = 0x11;
fn calculate_checksum(buffer: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < buffer.len() - 1 {
        let word = u16::from_be_bytes([buffer[i], buffer[i + 1]]);
        sum = sum.wrapping_add(u32::from(word));
        i += 2;
    }
    if buffer.len() % 2 == 1 {
        sum = sum.wrapping_add(u32::from(buffer[buffer.len() - 1]) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn put_checksum(data: &mut [u8], offset: usize) {
    data[offset] = 0;
    data[offset + 1] = 0;
    let checksum = calculate_checksum(data).to_be_bytes();
    data[offset] = checksum[0];
    data[offset + 1] = checksum[1];
}

fn add_wrapper(packet: &mut [u8]) {
    // IPv4 Header
    match packet[9] {
        PROTO_TCP => {}
        PROTO_UDP => {
            packet[6] |= 0x80;
        }
        _ => unreachable!("Can only wrap TCP or UDP packets"),
    }
    packet[9] = PROTO_ICMP; // Protocol (ICMP)
    put_checksum(&mut packet[..20], 10);
}

fn rm_wrapper(packet: &mut [u8]) {
    match packet[6] & 0x80 {
        0 => {
            packet[9] = PROTO_TCP;
        }
        _ => {
            packet[9] = PROTO_UDP;
        }
    }
    packet[6] &= 0x7f;
    put_checksum(&mut packet[..20], 10);
}

#[inline]
fn should_warp(packet: &[u8]) -> bool {
    packet[9] == PROTO_TCP || packet[9] == PROTO_UDP
}

#[inline]
fn is_wrapped(packet: &[u8]) -> bool {
    packet[9] == PROTO_ICMP
}

fn display(packet: &[u8]) {
    use std::net::Ipv4Addr;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    match packet[9] {
        PROTO_ICMP => {
            println!(
                "ICMP {} -> {} ==>{}",
                src,
                dst,
                String::from_utf8_lossy(&packet[20..])
            );
        }
        PROTO_TCP => {
            let src_port = u16::from_be_bytes([packet[20], packet[21]]);
            let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
            println!("TCP {}:{} -> {}:{}", src, src_port, dst, dst_port);
        }
        PROTO_UDP => {
            let src_port = u16::from_be_bytes([packet[20], packet[21]]);
            let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
            println!("UDP {}:{} -> {}:{}", src, src_port, dst, dst_port);
        }
        _ => {
            println!("Unknown protocol");
        }
    }
}

fn handle_in() {
    let inbound = WinDivert::network(
        "inbound and ip and ((remoteAddr >= 10.161.0.0 and remoteAddr < 10.162.0.0)or(remoteAddr >= 10.211.0.0 and remoteAddr < 10.212.0.0))",
        0,
        WinDivertFlags::new(),
    )
    .unwrap();
    loop {
        // Receive a packet
        let mut buffer = [0u8; 65536];
        let mut packet = inbound.recv(Some(&mut buffer)).unwrap().to_owned();
        if is_wrapped(&packet.data) {
            rm_wrapper(packet.data.to_mut());
        }
        display(&packet.data);
        println!("Recv {:X?}", &packet.data);
        packet
            .recalculate_checksums(ChecksumFlags::new().set_no_icmp())
            .unwrap();
        inbound.send(&packet).unwrap();
    }
}
fn handle_out() {
    let outbound = WinDivert::network(
        "outbound and ip and ((remoteAddr >= 10.161.0.0 and remoteAddr < 10.162.0.0)or(remoteAddr >= 10.211.0.0 and remoteAddr < 10.212.0.0))",
        0,
        WinDivertFlags::new(),
    )
    .unwrap();
    loop {
        // Receive a packet
        let mut buffer = [0u8; 65536];
        let mut packet = outbound.recv(Some(&mut buffer)).unwrap();
        display(&packet.data);
        println!("Send {:X?}", &packet.data);
        if should_warp(&packet.data) {
            add_wrapper(packet.data.to_mut());
        }
        outbound.send(&packet).unwrap();
    }
}
fn main() {
    let handle1 = thread::spawn(handle_in);
    let handle2 = thread::spawn(handle_out);

    handle1.join().expect("Thread 1 panicked");
    handle2.join().expect("Thread 2 panicked");
}
