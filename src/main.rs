use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread::sleep;
use std::time::{Duration, Instant};
extern crate env_logger;
extern crate hex;
extern crate hex_literal;
extern crate itertools;
extern crate log;
extern crate macaddr;
extern crate time;
use hex_literal::hex;
use itertools::Itertools;
use macaddr::MacAddr6;
//use log::{debug, error, log_enabled, info, Level};

#[cfg(feature = "opensslcrypto")]
extern crate openssl;
#[cfg(feature = "opensslcrypto")]
use openssl::symm::{Cipher, Crypter, Mode};

#[cfg(not(feature = "opensslcrypto"))]
extern crate aes;
#[cfg(not(feature = "opensslcrypto"))]
extern crate block_modes;
#[cfg(not(feature = "opensslcrypto"))]
use aes::Aes128;
#[cfg(not(feature = "opensslcrypto"))]
use block_modes::{BlockMode, Cbc};
#[cfg(not(feature = "opensslcrypto"))]
use block_modes::block_padding::NoPadding;
// create an alias for convenience
#[cfg(not(feature = "opensslcrypto"))]
type Aes128Cbc = Cbc<Aes128, NoPadding>;

fn main() {
    env_logger::init();
    println!("Broadlink-rm-rust RUST_LOG loglevel {}", log::max_level());
    let local_ip = get_local_ip();
    println!("Got local ip: {}", local_ip);
    match local_ip {
        IpAddr::V4(ip) => {
            let mut device = discover(ip, Some(Duration::from_secs(5)));
            device.auth();
            match device {
                BL::SP2(_) => device.set_power(true),
                _ => (),
            };
            match device {
                BL::SP2(_) => device.check_power().unwrap(),
                BL::RM2(_) => device.check_temperature().unwrap(),
                //_ => false
            };

            let mut device = discover(ip, Some(Duration::from_secs(5)));
            device.auth();
            match device {
                BL::SP2(_) => device.set_power(true),
                _ => (),
            };
            match device {
                BL::SP2(_) => device.check_power().unwrap(),
                BL::RM2(_) => device.check_temperature().unwrap(),
                //_ => false
            };
            match device {
                BL::RM2(_) => device.get_firmware().unwrap(),
                _ => false,
            };
            match device {
                BL::RM2(_) => device.enter_learning().unwrap(),
                _ => false,
            };
        }
        _ => println!("no ipv4"),
    }
}

fn get_local_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    socket.connect("8.8.8.8:53").expect("connect failed");
    let addr = socket.local_addr().expect("Could not get local addr");
    addr.ip()
}

fn discover(local_ip: Ipv4Addr, timeout: Option<Duration>) -> BL {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), 0)).expect("bind failed");
    socket.set_broadcast(true).expect("set_broadcast failed");

    let addr = socket.local_addr().expect("Could not get local addr");
    let packet = hello_packet(local_ip, addr.port());
    log::debug!(
        "sending packet {:x?} on socket {:?}",
        hex::encode(&packet[0..0x30]),
        socket
    );
    socket
        .send_to(&packet, "255.255.255.255:80")
        .expect("couldn't send data");

    let mut buf = [0; 1024];
    socket
        .set_read_timeout(timeout)
        .expect("set_read_timeout failed");
    let (amt, src) = socket.recv_from(&mut buf).expect("read failed");
    log::info!("Data from {:?} : {:x?}", src, hex::encode(&buf[0..amt]));

    let device = gendevice(src, &buf);
    println!("Got device {:x?}", device);
    device
}

fn gendevice(src: SocketAddr, response: &[u8]) -> BL {
    let device_type: u16 = (response[0x34] as u16) | (response[0x35] as u16) << 8;
    println!("device type = {:x}", device_type);
    let mac = MacAddr6::new(
        response[0x3a],
        response[0x3b],
        response[0x3c],
        response[0x3d],
        response[0x3e],
        response[0x3f],
    );
    //macc.from(&response[0x3a..0x40]);
    //let mut mac = [0; 6];
    //mac.copy_from_slice(&response[0x3a..0x40]);
    match device_type {
        0x2728 => BL::SP2(SP2::new(String::from("SP2"), device_type, src, mac)),
        0x2737 => {
            println!("Broadlink RM Mini device type = {:x}", device_type);
            BL::RM2(RM::new(
                String::from("Broadlink RM Mini"),
                device_type,
                src,
                mac,
            ))
        }
        // has RF
        0x272a => {
            println!("Broadlink RM2 Pro Plus device type = {:x}", device_type);
            BL::RM2(RM::new(
                String::from("Broadlink RM2 Pro Plus"),
                device_type,
                src,
                mac,
            ))
        }
        _ => panic!("Unsupported device type {}", device_type),
    }
}

fn hello_packet(local_ip: Ipv4Addr, port: u16) -> [u8; 0x30] {
    let now = time::now();
    let timezone_offset: i32 = now.tm_utcoff / 3600 * -1;
    let mut packet: [u8; 0x30] = [0; 0x30];
    if timezone_offset < 0 {
        packet[0x08] = (0xff + (timezone_offset) - 1) as u8;
        packet[0x09] = 0xff;
        packet[0x0a] = 0xff;
        packet[0x0b] = 0xff;
    } else {
        packet[0x08] = timezone_offset as u8;
    }
    let year = now.tm_year + 1900;
    packet[0x0c] = (year & 0xff) as u8;
    packet[0x0d] = (year >> 8) as u8;
    packet[0x0e] = now.tm_min as u8;
    packet[0x0f] = now.tm_hour as u8;
    packet[0x10] = (now.tm_year + 1900 - 2000) as u8;
    packet[0x11] = now.tm_wday as u8;
    packet[0x12] = now.tm_mday as u8;
    packet[0x13] = now.tm_mon as u8;
    packet[0x18] = local_ip.octets()[0];
    packet[0x19] = local_ip.octets()[1];
    packet[0x1a] = local_ip.octets()[2];
    packet[0x1b] = local_ip.octets()[3];
    packet[0x1c] = (port & 0xff) as u8;
    packet[0x1d] = (port >> 8) as u8;
    packet[0x26] = 6;
    let mut checksum: i32 = 0xbeaf;

    for i in 0..packet.len() {
        checksum += packet[i] as i32;
    }
    packet[0x20] = (checksum & 0xff) as u8;
    packet[0x21] = (checksum >> 8) as u8;
    packet
}
#[repr(u8)]
enum RmCmd {
    CheckSensors = 0x01,
    SendData = 0x02,
    LearnIr = 0x03,
    CheckData = 0x04,
    SweepFrequency = 0x19,
    CheckFrequency = 0x1A,
    LearnRf = 0x1B,
    CancelSweepFrequency = 0x1E,
    GetFirmware = 0x68,
}

trait BroadlinkDevice {
    fn auth(&mut self) {
        let mut payload = [0u8; 0x50];
        payload[0x04] = 0x31;
        payload[0x05] = 0x31;
        payload[0x06] = 0x31;
        payload[0x07] = 0x31;
        payload[0x08] = 0x31;
        payload[0x09] = 0x31;
        payload[0x0a] = 0x31;
        payload[0x0b] = 0x31;
        payload[0x0c] = 0x31;
        payload[0x0d] = 0x31;
        payload[0x0e] = 0x31;
        payload[0x0f] = 0x31;
        payload[0x10] = 0x31;
        payload[0x11] = 0x31;
        payload[0x12] = 0x31;

        payload[0x1e] = 0x01;
        payload[0x2d] = 0x01;

        payload[0x30] = 'T' as u8;
        payload[0x31] = 'e' as u8;
        payload[0x32] = 's' as u8;
        payload[0x33] = 't' as u8;
        payload[0x34] = ' ' as u8;
        payload[0x35] = ' ' as u8;
        payload[0x36] = '1' as u8;

        let response = self.send_packet(0x65, &payload);
        let err: u16 = (response[0x22] as u16) | (response[0x23] as u16) << 8;
        let command: u8 = response[0x26]; // 0xe9 auth, 0xee or 0xef payload
                                          //  check_error(response[0x22:0x24])
        if response.len() > 0x38 {
            let r = &response[0x38..];
            log::debug!(
                "Auth response payload len = {}: {:x?}",
                r.len(),
                hex::encode(r)
            );

            let decrypted_payload = self.decrypt(&response[0x38..]);
            let param: u8 = decrypted_payload[0];

            log::debug!(
                "Auth response err/cmd/par = {}/{:02x}/{:02x} len = {}",
                err,
                command,
                param,
                decrypted_payload.len()
            );

            let mut id = [0u8; 4];
            id.clone_from_slice(&decrypted_payload[0x00..0x04]);
            let mut key = [0u8; 16];
            key.clone_from_slice(&decrypted_payload[0x04..0x14]);

            self.device_info_mut().id = id;
            self.device_info_mut().key = key;
        } else {
            log::debug!(
                "Auth response err/cmd = {}/{:02x} len = {}",
                err,
                command,
                response.len()
            );
            println!("No response from device on auth request :(");
        }
    }

    fn send_packet(&mut self, command: u8, payload: &[u8]) -> Vec<u8> {
        let packet = self.make_packet(command, payload);
        let socket = &self.device_info().socket;
        socket
            .send_to(&packet, self.device_info().addr)
            .expect("couldn't send data");

        log::debug!("Send {}: {:x?}", packet.len(), hex::encode(packet));
        let timeout = Some(Duration::from_secs(5));
        socket
            .set_read_timeout(timeout)
            .expect("set_read_timeout failed");
        let mut vec = Vec::new();
        let mut buf = [0; 2048];
        let (amt, _) = socket.recv_from(&mut buf).expect("read failed");
        vec.extend_from_slice(&buf[0..amt]);
        log::debug!("Received {}: {:x?}", amt, hex::encode(&buf[0..amt]));
        vec
    }

    fn send_packet0x6a_ex(&mut self, payload: &[u8]) -> (u16, u8, u8, Vec<u8>) {
        let response = self.send_packet(0x6a, &payload);
        let err = (response[0x22] as u16) | ((response[0x23] as u16) << 8);
        let command: u8 = response[0x26]; // 0xe9 auth, 0xee or 0xef payload
        if err == 0 {
            let payload = self.decrypt(&response[0x38..]);
            let param: u8 = payload[0];
            log::debug!(
                "send_packet0x6a response err/cmd/par = {}/{:02x}/{:02x} len = {}",
                err,
                command,
                param,
                payload.len()
            );
            return (err, command, param, payload);
        } else {
            return (err, command, 0, response);
        }
    }

    fn send_packet0x6a(&mut self, packet0: RmCmd) -> (u16, u8, u8, Vec<u8>) {
        let mut payload: [u8; 16] = [0; 16];
        payload[0] = packet0 as u8;
        self.send_packet0x6a_ex(&payload)
    }

    fn make_packet(&mut self, command: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet: Vec<u8> = vec![0u8; 0x38];
        self.device_info_mut().incr_count();
        packet[0x00] = 0x5a;
        packet[0x01] = 0xa5;
        packet[0x02] = 0xaa;
        packet[0x03] = 0x55;
        packet[0x04] = 0x5a;
        packet[0x05] = 0xa5;
        packet[0x06] = 0xaa;
        packet[0x07] = 0x55;

        packet[0x24] = 0x2a;
        packet[0x25] = 0x27;
        packet[0x26] = command;

        packet[0x28] = self.device_info().count as u8;
        packet[0x29] = (self.device_info().count >> 8) as u8;
        let mut mac = [0; 6];
        mac.copy_from_slice(self.device_info().mac.as_bytes());
        packet[0x2a] = mac[0]; // reversed in JS bus seems OK
        packet[0x2b] = mac[1];
        packet[0x2c] = mac[2];
        packet[0x2d] = mac[3];
        packet[0x2e] = mac[4];
        packet[0x2f] = mac[5];
        //packet[0x2a] = self.device_info().mac[0]; // reversed in JS bus seems OK
        //packet[0x2b] = self.device_info().mac[1];
        //packet[0x2c] = self.device_info().mac[2];
        //packet[0x2d] = self.device_info().mac[3];
        //packet[0x2e] = self.device_info().mac[4];
        //packet[0x2f] = self.device_info().mac[5];
        packet[0x30] = self.device_info().id[0];
        packet[0x31] = self.device_info().id[1];
        packet[0x32] = self.device_info().id[2];
        packet[0x33] = self.device_info().id[3];

        // pad the payload
        let padded_payload: Vec<u8> = if (payload.len() % 16) != 0 {
            let numpad = (payload.len() / 16 + 1) * 16;
            let zeroes_to_add = numpad - payload.len();
            log::debug!(
                "Padding Payload {} numpad {} zeroes_to_add {}",
                payload.len(),
                numpad,
                zeroes_to_add
            );
            let mut out: Vec<u8> = Vec::with_capacity(numpad);
            for _ in 0..zeroes_to_add {
                out.push(0u8);
            }
            out.extend_from_slice(payload);
            out
        } else {
            //Vec::new()
            let mut out: Vec<u8> = Vec::with_capacity(payload.len());
            out.extend_from_slice(payload);
            out
        };

        // payload checksum
        let payload_checksum = self.checksum(&padded_payload);
        packet[0x34] = payload_checksum as u8;
        packet[0x35] = (payload_checksum >> 8) as u8;

        // encrypt payload
        let mut encrypted_payload = self.encrypt(&padded_payload);
        // RKR encryption enlarges and that is wrong!
        encrypted_payload.resize(padded_payload.len(), 0);
        // append encrypted payload to packet
        packet.extend_from_slice(&encrypted_payload);

        // packet checksum
        let packet_checksum = self.checksum(&packet);
        packet[0x20] = packet_checksum as u8;
        packet[0x21] = (packet_checksum >> 8) as u8;
        packet
    }

    #[cfg(feature = "opensslcrypto")]
    fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        /*
        let cipher = Cipher::aes_128_cbc();
        let result = openssl::symm::encrypt(
            cipher,
            &self.device_info().key,
            Some(&self.device_info().iv),
            payload,
        );
        let r = result.unwrap();
        r
        */
        let mut encrypter = Crypter::new(
            Cipher::aes_128_cbc(),
            Mode::Encrypt,
            &self.device_info().key,
            Some(&self.device_info().iv),
        )
        .unwrap();
        encrypter.pad(false);
        let block_size = Cipher::aes_128_cbc().block_size();
        let mut ciphertext = vec![0; payload.len() + block_size];

        let mut count = encrypter.update(payload, &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);
        ciphertext
    }

    #[cfg(feature = "opensslcrypto")]
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        //println!("Decrypting {} {:?}", ciphertext.len(), ciphertext);
        //let cipher = openssl::symm::Cipher::aes_128_cbc();
        /*
        //Data is decrypted using the specified cipher type t in decrypt mode with the specified key and initailization vector iv. Padding is enabled.
        let result = openssl::symm::decrypt(
            cipher,
            &self.device_info().key,
            Some(&self.device_info().iv),
            payload,
        );
        result.unwrap();
        */
        let mut decrypter = Crypter::new(
            Cipher::aes_128_cbc(),
            Mode::Decrypt,
            &self.device_info().key,
            Some(&self.device_info().iv),
        )
        .unwrap();
        decrypter.pad(false);
        let block_size = Cipher::aes_128_cbc().block_size();
        let mut payload = vec![0; ciphertext.len() + block_size];

        let mut count = decrypter.update(ciphertext, &mut payload).unwrap();
        count += decrypter.finalize(&mut payload[count..]).unwrap();
        payload.truncate(count);
        payload
    }

    #[cfg(not(feature = "opensslcrypto"))]
    fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
    	let cipher = Aes128Cbc::new_from_slices(&self.device_info().key, &self.device_info().iv).unwrap();
    	/*
        let block_size = Cipher::aes_128_cbc().block_size();
        let mut ciphertext = vec![0; payload.len() + block_size];

        let mut count = encrypter.update(payload, &mut ciphertext).unwrap();
        count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);
        ciphertext
        */
        cipher.encrypt_vec(payload)
    }

    #[cfg(not(feature = "opensslcrypto"))]
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
    	let cipher = Aes128Cbc::new_from_slices(&self.device_info().key, &self.device_info().iv).unwrap();
    	/*
        let block_size = Cipher::aes_128_cbc().block_size();
        let mut payload = vec![0; ciphertext.len() + block_size];

        let mut count = decrypter.update(ciphertext, &mut payload).unwrap();
        count += decrypter.finalize(&mut payload[count..]).unwrap();
        payload.truncate(count);
        payload
        */
        cipher.decrypt_vec(&ciphertext).unwrap()
    }

    fn checksum(&self, buffer: &[u8]) -> u16 {
        let checksum: u32 = 0xbeaf;
        buffer
            .iter()
            .fold(checksum, |acc, &x| (acc + x as u32) & 0xffff) as u16
    }

    fn device_info(&self) -> &BroadlinkDeviceInfo;
    fn device_info_mut(&mut self) -> &mut BroadlinkDeviceInfo;
}

#[derive(Debug)]
struct BroadlinkDeviceInfo {
    device_type: String,
    device_type_nr: u16,
    addr: SocketAddr,
    //mac: [u8; 6],
    mac: MacAddr6,
    count: u16,
    id: [u8; 4],
    key: [u8; 16],
    iv: [u8; 16],
    socket: UdpSocket,
}

impl BroadlinkDeviceInfo {
    fn new(
        device_type: String,
        device_type_nr: u16,
        addr: SocketAddr,
        mac: MacAddr6,
    ) -> BroadlinkDeviceInfo {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not bind socket");
        socket.set_broadcast(true).expect("Could not set broadcast");
        BroadlinkDeviceInfo {
            device_type,
            device_type_nr,
            addr,
            mac,
            count: 0,
            id: [0; 4],
            key: hex!("097628343fe99e23765c1513accf8b02"),
            iv: hex!("562e17996d093d28ddb3ba695a2e6f58"),
            socket,
        }
    }

    fn incr_count(&mut self) {
        self.count = self.count + 1;
    }
}

#[derive(Debug)]
struct SP2 {
    device_info: BroadlinkDeviceInfo,
}

impl SP2 {
    fn new(device_type: String, device_type_nr: u16, addr: SocketAddr, mac: MacAddr6) -> SP2 {
        SP2 {
            device_info: BroadlinkDeviceInfo::new(device_type, device_type_nr, addr, mac),
        }
    }

    fn check_power(&mut self) -> Result<bool, &'static str> {
        let (err, _command, _param, payload) = self.send_packet0x6a(RmCmd::CheckSensors);
        if err == 0 {
            let status = payload[0x4];
            Ok(status > 0)
        } else {
            Err("got error response")
        }
    }

    fn set_power(&mut self, state: bool) {
        let mut payload = [0u8; 16];
        payload[0] = 2;
        payload[4] = state as u8;
        self.send_packet(0x6a, &payload);
    }
}

impl BroadlinkDevice for SP2 {
    fn device_info(&self) -> &BroadlinkDeviceInfo {
        &self.device_info
    }

    fn device_info_mut(&mut self) -> &mut BroadlinkDeviceInfo {
        &mut self.device_info
    }
}

#[derive(Debug)]
struct RM {
    device_info: BroadlinkDeviceInfo,
}

#[derive(Debug)]
enum BL {
    RM2(RM),
    SP2(SP2),
}

impl RM {
    fn new(device_type: String, device_type_nr: u16, addr: SocketAddr, mac: MacAddr6) -> RM {
        RM {
            device_info: BroadlinkDeviceInfo::new(device_type, device_type_nr, addr, mac),
        }
    }
    fn check_temperature(&mut self) -> Result<bool, &'static str> {
        let (err, command, param, payload) = self.send_packet0x6a(RmCmd::CheckSensors);
        if err == 0 {
            log::debug!(
                "check_temperature response err/cmd/par = {}/{:02x}/{:02x} len = {}",
                err,
                command,
                param,
                payload.len()
            );
            let t: f32 = (payload[0x4] * 10 + payload[0x5]).into();
            let temp = t / 10.0;
            println!("Temp {}", temp);
            let status = 1;
            Ok(status > 0)
        } else {
            Err("got error response")
        }
    }

    fn get_firmware(&mut self) -> Result<bool, &'static str> {
        let (err, command, param, payload) = self.send_packet0x6a(RmCmd::GetFirmware);
        if err == 0 {
            log::debug!(
                "get_firmware response err/cmd/par = {}/{:02x}/{:02x} len = {}",
                err,
                command,
                param,
                payload.len()
            );
            let firmware: u16 = (payload[0x4] as u16) | ((payload[0x5] as u16) << 8);
            println!("Firmware {}", firmware);
            let status = 1;
            Ok(status > 0)
        } else {
            Err("got error response")
        }
    }

    fn enter_learning(&mut self) -> Result<bool, &'static str> {
        // IR is 03, RF = 0x1B
        let one_sec = Duration::from_secs(1);
        let thirty_secs = Duration::from_secs(30);
        let (err, _command, _param, _payload) = self.send_packet0x6a(RmCmd::SweepFrequency);
        let mut sweep_ok = false;
        if err == 0 {
            let start = Instant::now();
            while start.elapsed() < thirty_secs {
                sleep(one_sec);
                let (err, command, param, payload) = self.send_packet0x6a(RmCmd::CheckFrequency);
                if err == 0 {
                    log::debug!(
                        "checkData sweep err/cmd/par = {}/{:02x}/{:02x} len = {} {:x?}",
                        err,
                        command,
                        param,
                        payload.len(),
                        hex::encode(&payload[0..payload.len()])
                    );
                    println!("Sweep OK {}", payload[0x4]);
                    sweep_ok = payload[0x4] != 0;
                    if sweep_ok {
                    	break;
                    }
                } else {
                    println!(
                        "checkData sweep error err/cmd/par = {}/{:02x}/{:02x} len = {}",
                        err,
                        command,
                        param,
                        payload.len()
                    )
                }
            }
        }
        if !sweep_ok {
            self.send_packet0x6a(RmCmd::CancelSweepFrequency);
        }
        let (err, command, param, payload) = self.send_packet0x6a(RmCmd::LearnRf);
	/*
        let mut payload: [u8; 16] = [0; 16];
        let freq: u32 = 433920; // 433.920 * 1000
	payload[0] = RmCmd::LearnRf as u8;
	payload[1] = (freq & 0xff) as u8;
	payload[2] = ((freq >> 8) & 0xff) as u8;
	payload[3] = ((freq >> 16) & 0xff) as u8;
	payload[4] = ((freq >> 24) & 0xff) as u8;
	//payload[1..5] = freq.to_le_bytes();
        let (err, command, param, payload) = self.send_packet0x6a_ex(&payload);
	    log::debug!(
		"enter_learning response err/cmd/par = {}/{:02x}/{:02x} len = {}",
		err,
		command,
		param,
		payload.len()
	    );
	// gives err 65532/ee/00 len = 72
	*/
        if err == 0 {
            log::debug!(
                "enter_learning response err/cmd/par = {}/{:02x}/{:02x} len = {}",
                err,
                command,
                param,
                payload.len()
            );
            let start = Instant::now();
            while start.elapsed() < thirty_secs {
                sleep(one_sec);
                let (err, command, param, payload) = self.send_packet0x6a(RmCmd::CheckData);
                if err == 0 {
                    println!(
                        "checkData04 response err/cmd/par = {}/{:02x}/{:02x} len = {} {:x?}",
                        err,
                        command,
                        param,
                        payload.len(),
                        hex::encode(&payload[0..payload.len()])
                    );
                    let signal_type = match payload[4] {
                        0x26 => "ir",
                        0xb2 => "ook433",
                        0xd7 => "ook315",
                        _ => "?",
                    };
                    let repeat = payload[5];
                    let pulse_gap_count = (payload[0x6] as u16) | (payload[0x7] as u16) << 8;
                    let _psg = std::cmp::min(pulse_gap_count, (payload.len() - 8) as u16);
                    let mut micros: Vec<u16> = Vec::with_capacity(pulse_gap_count.into());
                    let ticks = &payload[8..];
                    let mut micro_count = 0;

                    for mut i in 0..ticks.len() - 1 {
                        let mut pg = ticks[i] as u16;
                        if pg == 0 && (i + 2 < ticks.len()) {
                            // 0 then big endian 2 bytes
                            pg = ((ticks[i + 1] as u16) << 8) | (ticks[i + 2] as u16);
                            i += 2;
                        }
                        let micro = pg as u32 * 8192 / 269;
                        // todo 0005dc or 45680 is space timeout for RF
                        micro_count += 1;
                        micros.push(micro as u16); /* 30.51757 // 2^-15 seconds */ 
                        if payload[4] == 0xb2 && micro >= 45680 {
                        	break;
                        }
                        if micro_count >= pulse_gap_count {
                            break;
                        }
                    }
                    let counts = micros.clone().into_iter().counts();
                    let mut sorted: Vec<_> = counts.iter().collect();
                    sorted.sort_by_key(|a| a.0);
                    println!("Time {:?}", sorted);

                    sorted.sort_by_key(|a| a.1);
                    sorted.reverse();
                    println!("Count {:?}", sorted);

                    println!(
                        "Signaltype {} {:02x} Repeat {} PGC {} len {} Frequency {:?} Micros {:?}",
                        signal_type,
                        payload[4],
                        repeat,
                        pulse_gap_count,
                        payload.len() - 8,
                        counts,
                        micros
                    );

                    break;
                } else {
                    log::debug!(
                        "checkData04 error err/cmd/par = {}/{:02x}/{:02x} len = {}",
                        err,
                        command,
                        param,
                        payload.len()
                    )
                }
            }
            //let firmware: u16 = (payload[0x4] as u16) | ((payload[0x5] as u16) << 8);
            //println!("Firmware {}", firmware);
            let status = 1;
            Ok(status > 0)
        } else {
            Err("got error response")
        }
    }
}

impl BroadlinkDevice for RM {
    fn device_info(&self) -> &BroadlinkDeviceInfo {
        &self.device_info
    }

    fn device_info_mut(&mut self) -> &mut BroadlinkDeviceInfo {
        &mut self.device_info
    }
}

impl BroadlinkDevice for BL {
    fn device_info(&self) -> &BroadlinkDeviceInfo {
        match self {
            BL::RM2(inner) => inner.device_info(),
            BL::SP2(inner) => inner.device_info(),
        }
    }

    fn device_info_mut(&mut self) -> &mut BroadlinkDeviceInfo {
        match self {
            BL::RM2(inner) => inner.device_info_mut(),
            BL::SP2(inner) => inner.device_info_mut(),
        }
    }
}

impl BL {
    fn check_temperature(&mut self) -> Result<bool, &'static str> {
        match self {
            BL::RM2(inner) => inner.check_temperature(),
            BL::SP2(_inner) => Err("No Temp for device"),
        }
    }

    fn get_firmware(&mut self) -> Result<bool, &'static str> {
        match self {
            BL::RM2(inner) => inner.get_firmware(),
            BL::SP2(_inner) => Err("No Firmware for device"),
        }
    }

    fn enter_learning(&mut self) -> Result<bool, &'static str> {
        match self {
            BL::RM2(inner) => inner.enter_learning(),
            BL::SP2(_inner) => Err("No Learning for device"),
        }
    }

    fn check_power(&mut self) -> Result<bool, &'static str> {
        match self {
            BL::RM2(_inner) => Err("No power for device"),
            BL::SP2(inner) => inner.check_power(),
        }
    }

    fn set_power(&mut self, state: bool) {
        match self {
            BL::RM2(_inner) => (),
            BL::SP2(inner) => inner.set_power(state),
        }
    }
}
