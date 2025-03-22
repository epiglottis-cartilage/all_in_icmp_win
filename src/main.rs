#![feature(ip_from)]
use windivert::prelude::{WinDivert, WinDivertFlags};
use windivert_sys::ChecksumFlags;

mod ipv4 {
    const PROTO_ICMP: u8 = 0x1;
    const PROTO_TCP: u8 = 0x6;
    const PROTO_UDP: u8 = 0x11;
    fn add_wrapper(packet: &mut [u8]) {
        match packet[9] {
            PROTO_TCP => {}
            PROTO_UDP => {
                packet[6] |= 0x80;
            }
            _ => unreachable!("Only wrap TCP or UDP packets"),
        }
        packet[9] = PROTO_ICMP;
    }

    fn rm_wrapper(packet: &mut [u8]) {
        match packet[6] & 0x80 {
            0x00 => {
                packet[9] = PROTO_TCP;
            }
            _ => {
                packet[9] = PROTO_UDP;
            }
        }
        packet[6] &= !0x80;
    }

    #[inline]
    fn should_warp(packet: &[u8]) -> bool {
        packet[9] == PROTO_TCP || packet[9] == PROTO_UDP
    }

    #[inline]
    fn is_wrapped(packet: &[u8]) -> bool {
        packet[9] == PROTO_ICMP
            && packet.len() > 22
            && !(packet[21] == 0 && (packet[20] == 0 || packet[20] == 8))
    }

    fn display(packet: &[u8]) {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let src = Ipv4Addr::from_octets(*packet[12..].first_chunk().unwrap());
        let dst = Ipv4Addr::from_octets(*packet[16..].first_chunk().unwrap());
        match packet[9] {
            PROTO_ICMP => {
                print!(
                    "ICMP {:>20} -> {:>20} {}",
                    src,
                    dst,
                    match packet[20] {
                        0 => "Echo Reply  ",
                        8 => "Echo Request",
                        _ => "Unknown     ",
                    }
                );
            }
            PROTO_TCP => {
                let src = SocketAddrV4::new(src, u16::from_be_bytes([packet[20], packet[21]]));
                let dst = SocketAddrV4::new(dst, u16::from_be_bytes([packet[22], packet[23]]));
                print!("TCP  {:>20} -> {:<20}", src, dst);
            }
            PROTO_UDP => {
                let src = SocketAddrV4::new(src, u16::from_be_bytes([packet[20], packet[21]]));
                let dst = SocketAddrV4::new(dst, u16::from_be_bytes([packet[22], packet[23]]));
                print!("UDP  {:>20} -> {:<20}", src, dst);
            }
            _ => {
                print!("Unknown protocol {:X}", packet[9]);
            }
        }
        println!("\tlen:[{}]", packet.len());
    }
    pub fn handle(packet: &mut [u8]) {
        if is_wrapped(packet) {
            rm_wrapper(packet);
            display(packet);
        } else if should_warp(packet) {
            display(packet);
            add_wrapper(packet);
        } else {
            display(packet);
        }
    }
}
mod ipv6 {
    const PROTO_ICMPV6: u8 = 0x3A;
    const PROTO_TCP: u8 = 0x6;
    const PROTO_UDP: u8 = 0x11;

    fn add_wrapper(packet: &mut [u8]) {
        match packet[6] {
            PROTO_TCP => {
                packet[1] |= 0xE0;
            }
            PROTO_UDP => {
                packet[1] |= 0xC0;
            }
            _ => unreachable!("Only wrap TCP or UDP packets"),
        }
        packet[6] = PROTO_ICMPV6;
    }

    fn rm_wrapper(packet: &mut [u8]) {
        let traffic_class = packet[1];
        let proto = match traffic_class & 0xE0 {
            0xE0 => PROTO_TCP,
            0xC0 => PROTO_UDP,
            _ => unreachable!("Unknown mark {:X}", traffic_class),
        };
        packet[6] = proto;
        packet[1] &= !0xE0;
    }

    #[inline]
    fn should_wrap(packet: &[u8]) -> bool {
        packet[6] == PROTO_TCP || packet[6] == PROTO_UDP
    }

    #[inline]
    fn is_wrapped(packet: &[u8]) -> bool {
        packet[6] == PROTO_ICMPV6
            && packet[1] & !0xE0 != 0
            && packet.len() > 42
            && !(packet[41] == 0 && (packet[40] == 0 || packet[40] == 128))
    }

    fn display(packet: &[u8]) {
        use std::net::{Ipv6Addr, SocketAddrV6};
        let src = Ipv6Addr::from_octets(*packet[8..].first_chunk().unwrap());
        let dst = Ipv6Addr::from_octets(*packet[24..].first_chunk().unwrap());

        match packet[6] {
            PROTO_ICMPV6 => {
                print!(
                    "ICMP {:>46} -> {:<46} {}",
                    src,
                    dst,
                    match packet[40] {
                        0 => "Echo Reply  ",
                        128 => "Echo Request",
                        _ => "Unknown     ",
                    }
                );
            }
            PROTO_TCP => {
                let src =
                    SocketAddrV6::new(src, u16::from_be_bytes([packet[24], packet[25]]), 0, 0);
                let dst =
                    SocketAddrV6::new(dst, u16::from_be_bytes([packet[26], packet[27]]), 0, 0);
                print!("TCP  {:>46} -> {:<46}", src, dst);
            }
            PROTO_UDP => {
                let src =
                    SocketAddrV6::new(src, u16::from_be_bytes([packet[24], packet[25]]), 0, 0);
                let dst =
                    SocketAddrV6::new(dst, u16::from_be_bytes([packet[26], packet[27]]), 0, 0);
                print!("UDP  {:>46} -> {:<46}", src, dst);
            }
            _ => {
                print!("Unknown protocol {:X}", packet[6]);
            }
        }
        println!("\tlen:[{}]", packet.len());
    }

    pub fn handle(packet: &mut [u8]) {
        if is_wrapped(packet) {
            rm_wrapper(packet);
            display(packet);
        } else if should_wrap(packet) {
            display(packet);
            add_wrapper(packet);
        } else {
            display(packet);
        }
    }
}
fn handle() {
    let filter = WinDivert::network(
        String::from_utf8(std::fs::read("filter.cfg").expect("Cannot read filter.cfg")).unwrap(),
        0,
        WinDivertFlags::new().set_fragments(),
    )
    .expect("Run as admin?");
    loop {
        // Receive a packet
        let mut buffer = [0u8; 65536];
        let mut packet = filter.recv(Some(&mut buffer)).unwrap().to_owned();
        match packet.data[0] >> 4 {
            4 => ipv4::handle(packet.data.to_mut()),
            6 => ipv6::handle(packet.data.to_mut()),
            x @ _ => {
                println!("Unknown IP protocol {}", x);
            }
        }
        packet
            .recalculate_checksums(ChecksumFlags::new().set_no_icmp().set_no_icmpv6())
            .unwrap();
        filter.send(&packet).unwrap();
    }
}

fn main() {
    handle();
}
