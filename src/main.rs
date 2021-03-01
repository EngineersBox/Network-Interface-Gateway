extern crate pnet;
extern crate etherparse;
extern crate slog;
extern crate slog_term;
extern crate slog_async;
extern crate slog_json;
extern crate lazy_static;

use std::fs::{File, OpenOptions};
use std::fs;
use std::sync::Mutex;
use lazy_static::lazy_static;
use slog::{Drain, Duplicate, Fuse, Logger, o, info, error};
use slog_async::{Async, OverflowStrategy};
use slog_json::Json;
use slog_term::{FullFormat, TermDecorator};
use pnet::datalink::{self, NetworkInterface, DataLinkReceiver, DataLinkSender};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use etherparse::{SlicedPacket, TransportSlice};
use std::fmt;

fn initialize_logging() ->  slog::Logger {
    let log_path: &str = "logs/";
    let directory_creation_message: &str;
    match fs::create_dir(log_path) {
        Ok(_) => { directory_creation_message = "Created logging directory"; },
        Err(_) => { directory_creation_message = "Logging directory already exists, skipping";}
    }

    let log_file_path: String = format!("{}{}{}",log_path,chrono::Utc::now().to_string(),".log");
    let file: File = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_file_path.as_str())
        .unwrap();

    let decorator: TermDecorator = TermDecorator::new().force_color().build();

    type FuseFFTD = Fuse<FullFormat<TermDecorator>>;
    type FuseJF = Fuse<Json<File>>;
    type FuseMD = Fuse<Mutex<Duplicate<FuseFFTD, FuseJF>>>;

    let d1: FuseFFTD = FullFormat::new(decorator).build().fuse();
    let d2: FuseJF = Json::default(file).fuse();
    let both: FuseMD = Mutex::new(Duplicate::new(d1, d2)).fuse();
    let both: Fuse<Async> = Async::new(both)
        .overflow_strategy(OverflowStrategy::Block)
        .build()
        .fuse();
    let log: Logger = Logger::root(both, o!());

    info!(log,"{}", directory_creation_message);
    log
}

lazy_static! {
    static ref LOGGER: Logger = initialize_logging();
}

enum NetInterface {
    WIFI,
    BLUETOOTHPAN,
    THUNDERBOLT1,
    THUNDERBOLT2,
    THUNDERBOLT3,
    THUNDERBOLT4,
    TUNDERBOLTBRIDGE
}

impl NetInterface {
    pub fn to_string(&self) -> String {
        format!("{}", self)
    }
}

// List these hardware ports with: networksetup -listallhardwareports
impl fmt::Display for NetInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            NetInterface::WIFI => "en0",
            NetInterface::BLUETOOTHPAN => "en11",
            NetInterface::THUNDERBOLT1 => "en1",
            NetInterface::THUNDERBOLT2 => "en2",
            NetInterface::THUNDERBOLT3 => "en3",
            NetInterface::THUNDERBOLT4 => "en4",
            NetInterface::TUNDERBOLTBRIDGE => "bridge0",
        })
    }
}

fn main() {
    let interface_name: NetInterface = NetInterface::WIFI;
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name.to_string();

    let interfaces: Vec<NetworkInterface> = datalink::interfaces();
    let interface: NetworkInterface = interfaces.into_iter().filter(interface_names_match).next().unwrap();

    let (mut tx, mut rx): (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet: EthernetPacket = EthernetPacket::new(packet).unwrap();
                tx.build_and_send(1, packet.packet().len(), &mut |new_packet| { handle_packet(new_packet, &packet); });
            },
            Err(e) => {
                error!(LOGGER, "An error occurred while reading: {}", e);
            }
        }
    }
}

fn handle_packet(new_packet: &mut [u8], packet: &EthernetPacket) {
    let mut new_packet: MutableEthernetPacket = MutableEthernetPacket::new(new_packet).unwrap();
    new_packet.clone_from(packet);
    let retrieved_packet: SlicedPacket = match SlicedPacket::from_ethernet(packet.packet()) {
        Err(value) => {
            error!(LOGGER, "Could not unpack packet {:?}", value);
            return
        },
        Ok(value) => {
            info!(LOGGER, "Link: {:?}", value.link);
            info!(LOGGER, "VLAN: {:?}", value.vlan);
            info!(LOGGER, "IP: {:?}", value.ip);
            info!(LOGGER, "Transport: {:?}", value.transport);
            info!(LOGGER, "Payload: {}", String::from_utf8_lossy(value.payload));
            value
        }
    };
    let transport_slice: Option<TransportSlice> = retrieved_packet.transport;
    if transport_slice.is_none() {
        error!(LOGGER, "No transport field assosciated with this packet");
        return
    }
    match transport_slice.unwrap() {
        TransportSlice::Tcp(header_slice) => info!(LOGGER, "TCP Header: {}", String::from_utf8_lossy(header_slice.options())),
        TransportSlice::Udp(header_slice) => info!(LOGGER, "UDP Header: {}", String::from_utf8_lossy(header_slice.slice()))
    }
}