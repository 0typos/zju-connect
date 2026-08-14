use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use rand::{RngCore, rngs::OsRng};
use rc4::{Key, KeyInit, Rc4, StreamCipher, consts::U16};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use sha1::Sha1;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};
use x509_parser::{parse_x509_certificate, public_key::PublicKey};

use crate::Error;

const TLS_1_1: [u8; 2] = [0x03, 0x02];
const HANDSHAKE: u8 = 22;
const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const APPLICATION_DATA: u8 = 23;
const RC4_SHA: u16 = 0x0005;
const MAX_PLAINTEXT: usize = 16 * 1024;

type Rc4_128 = Rc4<U16>;

pub(super) struct LegacyTlsStream {
    socket: TcpStream,
    read: RecordCipher,
    write: RecordCipher,
}

impl LegacyTlsStream {
    pub(super) async fn connect(address: &str) -> Result<Self, Error> {
        let mut socket = TcpStream::connect(address).await?;
        socket.set_nodelay(true)?;

        let mut client_random = [0_u8; 32];
        OsRng.fill_bytes(&mut client_random);
        let client_hello = client_hello(client_random);
        write_plain_record(&mut socket, HANDSHAKE, &client_hello).await?;

        let mut transcript = client_hello;
        let (server_random, certificate) = read_server_flight(&mut socket, &mut transcript).await?;
        let public_key = rsa_key_from_certificate(&certificate)?;

        let mut premaster = [0_u8; 48];
        premaster[..2].copy_from_slice(&TLS_1_1);
        OsRng.fill_bytes(&mut premaster[2..]);
        let encrypted = public_key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, &premaster)
            .map_err(|error| Error::Protocol(format!("TLS RSA key exchange failed: {error}")))?;
        let mut key_exchange_body = Vec::with_capacity(2 + encrypted.len());
        push_u16(&mut key_exchange_body, encrypted.len())?;
        key_exchange_body.extend_from_slice(&encrypted);
        let key_exchange = handshake_message(16, &key_exchange_body)?;
        write_plain_record(&mut socket, HANDSHAKE, &key_exchange).await?;
        transcript.extend_from_slice(&key_exchange);

        let master = tls_prf(
            &premaster,
            b"master secret",
            &[client_random.as_slice(), server_random.as_slice()].concat(),
            48,
        );
        let key_block = tls_prf(
            &master,
            b"key expansion",
            &[server_random.as_slice(), client_random.as_slice()].concat(),
            72,
        );
        let mut client_write = RecordCipher::new(&key_block[0..20], &key_block[40..56])?;
        let server_read = RecordCipher::new(&key_block[20..40], &key_block[56..72])?;

        write_plain_record(&mut socket, CHANGE_CIPHER_SPEC, &[1]).await?;
        let verify = finished_verify(&master, b"client finished", &transcript);
        let client_finished = handshake_message(20, &verify)?;
        let encrypted_finished = client_write.encrypt(HANDSHAKE, &client_finished)?;
        write_raw_record(&mut socket, HANDSHAKE, &encrypted_finished).await?;
        transcript.extend_from_slice(&client_finished);

        let (record_type, change_cipher) = read_raw_record(&mut socket).await?;
        if record_type != CHANGE_CIPHER_SPEC || change_cipher.as_slice() != [1] {
            return Err(Error::Protocol(
                "legacy TLS server omitted ChangeCipherSpec".into(),
            ));
        }
        let mut stream = Self {
            socket,
            read: server_read,
            write: client_write,
        };
        let (record_type, encrypted_server_finished) = read_raw_record(&mut stream.socket).await?;
        if record_type != HANDSHAKE {
            return Err(Error::Protocol(format!(
                "expected encrypted TLS Finished, got record {record_type}"
            )));
        }
        let server_finished = stream.read.decrypt(HANDSHAKE, encrypted_server_finished)?;
        let expected = handshake_message(
            20,
            &finished_verify(&master, b"server finished", &transcript),
        )?;
        if server_finished != expected {
            return Err(Error::Protocol(
                "legacy TLS server Finished verification failed".into(),
            ));
        }
        Ok(stream)
    }

    pub(super) async fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        for chunk in data.chunks(MAX_PLAINTEXT) {
            let encrypted = self.write.encrypt(APPLICATION_DATA, chunk)?;
            write_raw_record(&mut self.socket, APPLICATION_DATA, &encrypted).await?;
        }
        Ok(())
    }

    pub(super) async fn read_record(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            let (record_type, encrypted) = read_raw_record(&mut self.socket).await?;
            let plaintext = self.read.decrypt(record_type, encrypted)?;
            match record_type {
                APPLICATION_DATA => return Ok(plaintext),
                ALERT => {
                    let description = plaintext.get(1).copied().unwrap_or_default();
                    return Err(Error::Protocol(format!(
                        "legacy TLS peer sent alert {description}"
                    )));
                }
                // Ignore post-handshake heartbeat/handshake messages. EasyConnect's
                // application protocol has its own liveness rules.
                22 | 24 => {}
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected encrypted TLS record type {other}"
                    )));
                }
            }
        }
    }
}

struct RecordCipher {
    mac_key: [u8; 20],
    cipher: Rc4_128,
    sequence: u64,
}

impl RecordCipher {
    fn new(mac_key: &[u8], cipher_key: &[u8]) -> Result<Self, Error> {
        let mac_key: [u8; 20] = mac_key
            .try_into()
            .map_err(|_| Error::Protocol("invalid TLS MAC key length".into()))?;
        let cipher = Rc4_128::new(Key::<U16>::from_slice(cipher_key));
        Ok(Self {
            mac_key,
            cipher,
            sequence: 0,
        })
    }

    fn encrypt(&mut self, record_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mac = record_mac(&self.mac_key, self.sequence, record_type, plaintext)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("TLS record sequence exhausted".into()))?;
        let mut output = Vec::with_capacity(plaintext.len() + mac.len());
        output.extend_from_slice(plaintext);
        output.extend_from_slice(&mac);
        self.cipher.apply_keystream(&mut output);
        Ok(output)
    }

    fn decrypt(&mut self, record_type: u8, mut ciphertext: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.cipher.apply_keystream(&mut ciphertext);
        if ciphertext.len() < 20 {
            return Err(Error::Protocol("encrypted TLS record is too short".into()));
        }
        let mac = ciphertext.split_off(ciphertext.len() - 20);
        let expected = record_mac(&self.mac_key, self.sequence, record_type, &ciphertext)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("TLS record sequence exhausted".into()))?;
        if mac != expected {
            return Err(Error::Protocol("legacy TLS record MAC mismatch".into()));
        }
        Ok(ciphertext)
    }
}

fn client_hello(random: [u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(80);
    body.extend_from_slice(&TLS_1_1);
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(b"L3IP\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    body.extend_from_slice(&4_u16.to_be_bytes());
    body.extend_from_slice(&RC4_SHA.to_be_bytes());
    body.extend_from_slice(&0x00ff_u16.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    // RFC 6520 heartbeat extension: type 0x000f, one-byte body, peer_allowed_to_send.
    body.extend_from_slice(&5_u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0x00, 0x01, 0x01]);
    handshake_message(1, &body).expect("fixed ClientHello fits in u24")
}

async fn read_server_flight(
    socket: &mut TcpStream,
    transcript: &mut Vec<u8>,
) -> Result<([u8; 32], Vec<u8>), Error> {
    let mut buffered = Vec::new();
    let mut server_random = None;
    let mut certificate = None;
    loop {
        let (record_type, fragment) = read_raw_record(socket).await?;
        if record_type == ALERT {
            return Err(Error::Protocol(format!(
                "legacy TLS handshake alert {}",
                fragment.get(1).copied().unwrap_or_default()
            )));
        }
        if record_type != HANDSHAKE {
            continue;
        }
        buffered.extend_from_slice(&fragment);
        loop {
            if buffered.len() < 4 {
                break;
            }
            let length = read_u24(&buffered[1..4]);
            if buffered.len() < 4 + length {
                break;
            }
            let message = buffered.drain(..4 + length).collect::<Vec<_>>();
            transcript.extend_from_slice(&message);
            match message[0] {
                2 => server_random = Some(parse_server_hello(&message[4..])?),
                11 => certificate = Some(parse_certificate(&message[4..])?),
                14 => {
                    return Ok((
                        server_random.ok_or_else(|| {
                            Error::Protocol("TLS server omitted ServerHello".into())
                        })?,
                        certificate.ok_or_else(|| {
                            Error::Protocol("TLS server omitted Certificate".into())
                        })?,
                    ));
                }
                _ => {}
            }
        }
    }
}

fn parse_server_hello(body: &[u8]) -> Result<[u8; 32], Error> {
    if body.len() < 38 || body[..2] != TLS_1_1 {
        return Err(Error::Protocol(
            "legacy TLS server did not negotiate TLS 1.1".into(),
        ));
    }
    let random: [u8; 32] = body[2..34]
        .try_into()
        .map_err(|_| Error::Protocol("invalid ServerHello random".into()))?;
    let session_length = usize::from(body[34]);
    let cipher_offset = 35 + session_length;
    if body.len() < cipher_offset + 3 {
        return Err(Error::Protocol("truncated TLS ServerHello".into()));
    }
    let cipher = u16::from_be_bytes([body[cipher_offset], body[cipher_offset + 1]]);
    if cipher != RC4_SHA {
        return Err(Error::Protocol(format!(
            "legacy TLS server selected unsupported cipher 0x{cipher:04x}"
        )));
    }
    Ok(random)
}

fn parse_certificate(body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() < 6 {
        return Err(Error::Protocol("truncated TLS Certificate".into()));
    }
    let list_length = read_u24(&body[..3]);
    let certificate_length = read_u24(&body[3..6]);
    if list_length + 3 > body.len() || certificate_length + 6 > body.len() {
        return Err(Error::Protocol("invalid TLS Certificate length".into()));
    }
    Ok(body[6..6 + certificate_length].to_vec())
}

fn rsa_key_from_certificate(der: &[u8]) -> Result<RsaPublicKey, Error> {
    let (_, certificate) = parse_x509_certificate(der)
        .map_err(|error| Error::Protocol(format!("invalid TLS certificate: {error}")))?;
    let PublicKey::RSA(key) = certificate
        .public_key()
        .parsed()
        .map_err(|error| Error::Protocol(format!("invalid TLS public key: {error}")))?
    else {
        return Err(Error::Protocol(
            "legacy TLS gateway certificate is not RSA".into(),
        ));
    };
    RsaPublicKey::new(
        BigUint::from_bytes_be(key.modulus),
        BigUint::from_bytes_be(key.exponent),
    )
    .map_err(|error| Error::Protocol(format!("invalid RSA certificate key: {error}")))
}

fn handshake_message(kind: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > 0x00ff_ffff {
        return Err(Error::Protocol("TLS handshake message is too large".into()));
    }
    let length = u32::try_from(body.len())
        .map_err(|_| Error::Protocol("TLS handshake message is too large".into()))?
        .to_be_bytes();
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    message.extend_from_slice(&length[1..]);
    message.extend_from_slice(body);
    Ok(message)
}

fn tls_prf(secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let split = secret.len().div_ceil(2);
    let left = &secret[..split];
    let right = &secret[secret.len() - split..];
    let seed = [label, seed].concat();
    let md5 = p_hash(left, &seed, length, hmac_md5);
    let sha1 = p_hash(right, &seed, length, hmac_sha1);
    md5.into_iter()
        .zip(sha1)
        .map(|(left, right)| left ^ right)
        .collect()
}

fn p_hash(secret: &[u8], seed: &[u8], length: usize, hmac: fn(&[u8], &[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut a = hmac(secret, seed);
    while output.len() < length {
        let block = hmac(secret, &[a.as_slice(), seed].concat());
        output.extend_from_slice(&block);
        a = hmac(secret, &a);
    }
    output.truncate(length);
    output
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

fn finished_verify(master: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    let md5 = Md5::digest(transcript);
    let sha1 = Sha1::digest(transcript);
    tls_prf(
        master,
        label,
        &[md5.as_slice(), sha1.as_slice()].concat(),
        12,
    )
}

fn record_mac(
    key: &[u8],
    sequence: u64,
    record_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(plaintext.len())
        .map_err(|_| Error::Protocol("TLS record is too large".into()))?;
    let mut input = Vec::with_capacity(13 + plaintext.len());
    input.extend_from_slice(&sequence.to_be_bytes());
    input.push(record_type);
    input.extend_from_slice(&TLS_1_1);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(plaintext);
    Ok(hmac_sha1(key, &input))
}

async fn write_plain_record(
    socket: &mut TcpStream,
    record_type: u8,
    plaintext: &[u8],
) -> Result<(), Error> {
    write_raw_record(socket, record_type, plaintext).await
}

async fn write_raw_record(
    socket: &mut TcpStream,
    record_type: u8,
    fragment: &[u8],
) -> Result<(), Error> {
    let length = u16::try_from(fragment.len())
        .map_err(|_| Error::Protocol("TLS record is too large".into()))?;
    socket.write_all(&[record_type, 0x03, 0x02]).await?;
    socket.write_all(&length.to_be_bytes()).await?;
    socket.write_all(fragment).await?;
    socket.flush().await?;
    Ok(())
}

async fn read_raw_record(socket: &mut TcpStream) -> Result<(u8, Vec<u8>), Error> {
    let mut header = [0_u8; 5];
    socket.read_exact(&mut header).await?;
    if header[1] != 3 || !matches!(header[2], 1 | 2) {
        return Err(Error::Protocol(format!(
            "unexpected TLS record version {}.{}",
            header[1], header[2]
        )));
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_PLAINTEXT + 2048 {
        return Err(Error::Protocol(format!(
            "TLS record length {length} exceeds limit"
        )));
    }
    let mut fragment = vec![0_u8; length];
    socket.read_exact(&mut fragment).await?;
    Ok((header[0], fragment))
}

fn push_u16(output: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    output.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| Error::Protocol("value does not fit in TLS u16".into()))?
            .to_be_bytes(),
    );
    Ok(())
}

fn read_u24(value: &[u8]) -> usize {
    (usize::from(value[0]) << 16) | (usize::from(value[1]) << 8) | usize::from(value[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_uses_l3ip_session_and_rc4_sha() {
        let hello = client_hello([0x42; 32]);
        assert_eq!(&hello[..4], &[1, 0, 0, 82]);
        assert_eq!(&hello[4..6], &TLS_1_1);
        assert_eq!(&hello[39..43], b"L3IP");
        assert!(
            hello
                .windows(2)
                .any(|window| window == RC4_SHA.to_be_bytes())
        );
    }

    #[test]
    fn record_cipher_round_trips_and_advances_stream() {
        let mac_key = [0x11; 20];
        let cipher_key = [0x22; 16];
        let mut writer = RecordCipher::new(&mac_key, &cipher_key).unwrap();
        let mut reader = RecordCipher::new(&mac_key, &cipher_key).unwrap();
        for message in [b"first".as_slice(), b"second packet".as_slice()] {
            let ciphertext = writer.encrypt(APPLICATION_DATA, message).unwrap();
            assert_ne!(ciphertext[..message.len()], *message);
            assert_eq!(
                reader.decrypt(APPLICATION_DATA, ciphertext).unwrap(),
                message
            );
        }
    }

    #[test]
    fn record_cipher_detects_tampering() {
        let mut writer = RecordCipher::new(&[1; 20], &[2; 16]).unwrap();
        let mut reader = RecordCipher::new(&[1; 20], &[2; 16]).unwrap();
        let mut ciphertext = writer.encrypt(APPLICATION_DATA, b"packet").unwrap();
        ciphertext[0] ^= 1;
        assert!(reader.decrypt(APPLICATION_DATA, ciphertext).is_err());
    }

    #[test]
    fn parse_server_hello_extracts_random_and_requires_rc4_sha() {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_1_1);
        let random = [0x5A_u8; 32];
        body.extend_from_slice(&random);
        body.push(4); // session id length
        body.extend_from_slice(&[0xAB; 4]);
        body.extend_from_slice(&RC4_SHA.to_be_bytes());
        body.push(0); // compression
        assert_eq!(parse_server_hello(&body).unwrap(), random);

        // A different cipher is rejected.
        let mut wrong = body.clone();
        let cipher_offset = 35 + 4;
        wrong[cipher_offset..cipher_offset + 2].copy_from_slice(&0x002f_u16.to_be_bytes());
        assert!(parse_server_hello(&wrong).is_err());

        // Truncation before the cipher suite is rejected without panicking.
        assert!(parse_server_hello(&body[..37]).is_err());
    }

    #[test]
    fn parse_certificate_returns_first_entry_and_rejects_bad_lengths() {
        let cert = [0xC0_u8; 20];
        let mut body = Vec::new();
        body.extend_from_slice(&read_u24_bytes(cert.len() + 3));
        body.extend_from_slice(&read_u24_bytes(cert.len()));
        body.extend_from_slice(&cert);
        assert_eq!(parse_certificate(&body).unwrap(), cert);

        // A certificate length exceeding the body is rejected, not sliced.
        let mut lying = Vec::new();
        lying.extend_from_slice(&read_u24_bytes(1000));
        lying.extend_from_slice(&read_u24_bytes(1000));
        lying.extend_from_slice(&[0; 4]);
        assert!(parse_certificate(&lying).is_err());
    }

    fn read_u24_bytes(value: usize) -> [u8; 3] {
        let bytes = u32::try_from(value).unwrap().to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }

    #[test]
    fn prf_is_deterministic_length_bound_and_secret_sensitive() {
        let a = tls_prf(b"secret-key", b"label", b"seed-value", 48);
        let b = tls_prf(b"secret-key", b"label", b"seed-value", 48);
        assert_eq!(a, b);
        assert_eq!(a.len(), 48);
        let c = tls_prf(b"secret-kex", b"label", b"seed-value", 48);
        assert_ne!(a, c);
        // Output must extend correctly across P_hash block boundaries.
        assert_eq!(tls_prf(b"k", b"l", b"s", 100).len(), 100);
    }

    #[test]
    fn finished_verify_is_twelve_bytes_and_transcript_sensitive() {
        let master = [0x33; 48];
        let a = finished_verify(&master, b"client finished", b"transcript-a");
        let b = finished_verify(&master, b"client finished", b"transcript-b");
        assert_eq!(a.len(), 12);
        assert_ne!(a, b);
    }
}
