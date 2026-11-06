use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use key_distribution::net::framing::{FramingError, LineReader, MAX_LINE, send_line, send_message};
use key_distribution::protocol::messages::Message;

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn send_line_rejects_line_breaks() {
    let (client, _server) = pair();
    assert!(matches!(
        send_line(&client, "bad\nline"),
        Err(FramingError::LineBreak)
    ));
    assert!(matches!(
        send_line(&client, "bad\rline"),
        Err(FramingError::LineBreak)
    ));
}

#[test]
fn line_roundtrips_over_a_socket() {
    let (client, server) = pair();
    send_line(&client, "STEP1|alice|bob|7311").unwrap();
    assert_eq!(
        LineReader::new(server).recv_line().unwrap().unwrap(),
        "STEP1|alice|bob|7311"
    );
}

#[test]
fn multiple_lines_in_one_send_are_split() {
    let (mut client, server) = pair();
    client.write_all(b"l1\nl2\nl3\n").unwrap();
    let mut reader = LineReader::new(server);
    assert_eq!(reader.recv_line().unwrap().unwrap(), "l1");
    assert_eq!(reader.recv_line().unwrap().unwrap(), "l2");
    assert_eq!(reader.recv_line().unwrap().unwrap(), "l3");
}

#[test]
fn fragmented_arrival_is_reassembled() {
    let (mut client, server) = pair();
    let text = format!("STEP2|{}", "A1B2C3D4E5F6078".repeat(100));
    let full = format!("{text}\n").into_bytes();

    let sender = thread::spawn(move || {
        for piece in full.chunks(7) {
            client.write_all(piece).unwrap();
            thread::sleep(Duration::from_millis(1));
        }
    });

    assert_eq!(LineReader::new(server).recv_line().unwrap().unwrap(), text);
    sender.join().unwrap();
}

#[test]
fn binary_safe_split_on_received_bytes() {
    let (mut client, server) = pair();
    let mut expected = String::new();
    expected.push_str(&"A".repeat(5000));
    expected.push_str(&"B".repeat(5000));

    client.write_all(&vec![b'A'; 5000]).unwrap();
    thread::sleep(Duration::from_millis(50));
    client.write_all(&vec![b'B'; 5000]).unwrap();
    client.write_all(b"\n").unwrap();

    assert_eq!(
        LineReader::new(server).recv_line().unwrap().unwrap(),
        expected
    );
}

#[test]
fn clean_close_returns_none() {
    let (client, server) = pair();
    drop(client);
    assert!(LineReader::new(server).recv_line().unwrap().is_none());
}

#[test]
fn mid_line_close_is_an_error() {
    let (mut client, server) = pair();
    client.write_all(b"half line").unwrap();
    drop(client);
    assert!(matches!(
        LineReader::new(server).recv_line(),
        Err(FramingError::ClosedMidLine(9))
    ));
}

#[test]
fn oversized_line_is_rejected() {
    let (mut client, server) = pair();
    let sender = thread::spawn(move || {
        let _ = client.write_all(&vec![b'X'; MAX_LINE + 1]);
    });

    assert!(matches!(
        LineReader::new(server).recv_line(),
        Err(FramingError::LineTooLong)
    ));
    sender.join().unwrap();
}

#[test]
fn messages_roundtrip_over_a_socket() {
    let (client, server) = pair();
    let message = Message::Bye;
    send_message(&client, &message).unwrap();
    assert_eq!(
        LineReader::new(server).recv_message().unwrap().unwrap(),
        message
    );
}

#[test]
fn invalid_json_is_rejected() {
    let (mut client, server) = pair();
    client.write_all(b"not json\n").unwrap();
    assert!(LineReader::new(server).recv_message().is_err());
}

#[test]
fn full_duplex_exchange_on_localhost() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        send_line(&stream, "{\"type\":\"bye\"}").unwrap();
        let mut reader = LineReader::new(stream);
        let received = reader.recv_message().unwrap().unwrap();
        assert_eq!(received, Message::Bye);
    });

    let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut reader = LineReader::new(client.try_clone().unwrap());
    assert_eq!(reader.recv_message().unwrap().unwrap(), Message::Bye);
    send_message(&client, &Message::Bye).unwrap();
    server.join().unwrap();
}
