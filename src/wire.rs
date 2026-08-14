//! Declarative wire framing for the gateway protocols.
//!
//! These [`binrw`] structures replace hand-rolled byte packing for the fixed
//! big-endian frame headers exchanged over the tunnel sockets. Parsing that
//! must tolerate interleaved or unknown frames stays in the protocol modules;
//! this module owns the layouts that are built for sending (and their
//! symmetric fixed-size reads).

use std::io::Cursor;

#[cfg(test)]
use binrw::{BinRead, meta::ReadEndian};
use binrw::{BinWrite, binrw, meta::WriteEndian};

use crate::Error;

/// Serialize a [`BinWrite`] value into a byte vector using its declared endianness.
pub(crate) fn to_bytes<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian,
{
    let mut cursor = Cursor::new(Vec::new());
    value
        .write(&mut cursor)
        .map_err(|error| Error::Protocol(format!("failed to encode wire frame: {error}")))?;
    Ok(cursor.into_inner())
}

/// Deserialize a [`BinRead`] value from a byte slice using its declared endianness.
///
/// Production paths only build frames; symmetric reads are exercised by the
/// round-trip tests, which is the guarantee this function underwrites.
#[cfg(test)]
pub(crate) fn from_bytes<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: for<'a> BinRead<Args<'a> = ()> + ReadEndian,
{
    let mut cursor = Cursor::new(bytes);
    T::read(&mut cursor)
        .map_err(|error| Error::Protocol(format!("failed to decode wire frame: {error}")))
}

/// `EasyConnect` L3 IP-address request: a zero command word, the 48-byte
/// session token, then the fixed suffix (eight zero bytes and the all-ones
/// address request marker).
#[binrw]
#[brw(big, magic = 0u32)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EcIpRequest {
    pub token: [u8; 48],
    #[brw(magic = b"\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff")]
    pub _suffix: (),
}

/// `EasyConnect` L3 send/receive tunnel handshake: a command byte, the 48-byte
/// token, eight zero bytes, then the virtual IP in reversed byte order.
#[binrw]
#[brw(big)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EcTunnelRequest {
    pub command: u8,
    #[brw(pad_before = 3)]
    pub token: [u8; 48],
    #[brw(pad_before = 8)]
    pub reversed_ip: [u8; 4],
}

/// aTrust L3 frame header: protocol version, command, and a big-endian length.
#[binrw]
#[brw(big, magic = 0x05u8)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AtrustL3Header {
    pub command: u8,
    pub length: u16,
}

/// aTrust L3 data-packet frame prefix: version, the data command, a
/// length-prefixed connection token, the fixed `00 00 01` address marker, and
/// the big-endian packet length. The IP packet body follows.
#[binrw]
#[brw(big, magic = 0x05u8)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AtrustDataHeader {
    #[brw(magic = 0x14u8)]
    pub token_length: u8,
    #[br(count = token_length)]
    pub token: Vec<u8>,
    #[brw(magic = b"\x00\x00\x01")]
    pub packet_length: u16,
}

/// The 12-byte DNS message header.
#[binrw]
#[brw(big)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authorities: u16,
    pub additionals: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_tunnel_request_matches_manual_layout() {
        let token = [0xABu8; 48];
        let ip = [10, 20, 30, 40];
        let request = EcTunnelRequest {
            command: 0x05,
            token,
            reversed_ip: {
                let mut reversed = ip;
                reversed.reverse();
                reversed
            },
        };
        let encoded = to_bytes(&request).unwrap();

        let mut manual = Vec::new();
        manual.extend_from_slice(&[0x05, 0, 0, 0]);
        manual.extend_from_slice(&token);
        manual.extend_from_slice(&[0; 8]);
        manual.extend(ip.into_iter().rev());
        assert_eq!(encoded, manual);
        assert_eq!(from_bytes::<EcTunnelRequest>(&encoded).unwrap(), request);
    }

    #[test]
    fn ec_ip_request_matches_manual_layout() {
        let token = [0x11u8; 48];
        let frame = to_bytes(&EcIpRequest { token, _suffix: () }).unwrap();
        let mut manual = vec![0, 0, 0, 0];
        manual.extend_from_slice(&token);
        manual.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(frame, manual);
    }

    #[test]
    fn atrust_l3_header_round_trips() {
        let header = AtrustL3Header {
            command: 0x13,
            length: 0x0142,
        };
        let encoded = to_bytes(&header).unwrap();
        assert_eq!(encoded, [0x05, 0x13, 0x01, 0x42]);
        assert_eq!(from_bytes::<AtrustL3Header>(&encoded).unwrap(), header);
    }

    #[test]
    fn atrust_data_header_matches_manual_layout() {
        let token = b"token-value".to_vec();
        let header = AtrustDataHeader {
            token_length: u8::try_from(token.len()).unwrap(),
            token: token.clone(),
            packet_length: 60,
        };
        let encoded = to_bytes(&header).unwrap();

        let mut manual = vec![0x05, 0x14, u8::try_from(token.len()).unwrap()];
        manual.extend_from_slice(&token);
        manual.extend_from_slice(&[0, 0, 1]);
        manual.extend_from_slice(&60_u16.to_be_bytes());
        assert_eq!(encoded, manual);
        assert_eq!(from_bytes::<AtrustDataHeader>(&encoded).unwrap(), header);
    }

    #[test]
    fn dns_header_round_trips() {
        let header = DnsHeader {
            id: 0x1234,
            flags: 0x0100,
            questions: 1,
            answers: 0,
            authorities: 0,
            additionals: 0,
        };
        let encoded = to_bytes(&header).unwrap();
        assert_eq!(&encoded[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(encoded.len(), 12);
        assert_eq!(from_bytes::<DnsHeader>(&encoded).unwrap(), header);
    }
}
