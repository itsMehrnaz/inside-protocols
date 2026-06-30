use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let packet: [u8; 43] = [
        0x30, 0x29,
            0x02, 0x01, 0x01,
            0x04, 0x06, 0x70,0x75,0x62,0x6c,0x69,0x63,
            0xa0, 0x1c,
                0x02, 0x04, 0x12,0x34,0x56,0x78,
                0x02, 0x01, 0x00,
                0x02, 0x01, 0x00,
                0x30, 0x0e,
                    0x30, 0x0c,
                        0x06, 0x08, 0x2b,0x06,0x01,0x02,0x01,0x01,0x05,0x00,
                        0x05, 0x00,
    ];

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.send_to(&packet, "127.0.0.1:161")?;
    println!("Sent {} bytes", packet.len());

    let mut buf = [0u8; 1500];
    let (n, src) = socket.recv_from(&mut buf)?;
    println!("Received {} bytes from {}", n, src);
    println!("Raw response: {:02x?}", &buf[..n]);

    if let Some(last) = buf[..n].iter().rposition(|&b| b == 0x04) {
        let len = buf[last + 1] as usize;
        let val = &buf[last + 2..last + 2 + len];
        println!("sysName = {}", String::from_utf8_lossy(val));
    }

    Ok(())
}
