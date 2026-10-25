import socket
import threading
import time
import unittest

from src.net.framing import MAX_LINE, recv_line, send_line


class TestSendLine(unittest.TestCase):
    def test_rejects_line_breaks(self):
        a, _ = socket.socketpair()
        with self.assertRaises(ValueError):
            send_line(a, "bad\nline")
        with self.assertRaises(ValueError):
            send_line(a, "bad\rline")

    def test_rejects_non_str(self):
        a, _ = socket.socketpair()
        with self.assertRaises(TypeError):
            send_line(a, b"bytes not str")

    def _cleanup(self, a, b):
        a.close()
        b.close()


class TestRecvLine(unittest.TestCase):
    def test_roundtrip_socketpair(self):
        a, b = socket.socketpair()
        send_line(a, "STEP1|alice|bob|7311")
        self.assertEqual(recv_line(b), "STEP1|alice|bob|7311")
        a.close()
        b.close()

    def test_multiple_lines_in_one_send(self):
        a, b = socket.socketpair()
        a.sendall(b"l1\nl2\nl3\n")
        self.assertEqual(recv_line(b), "l1")
        self.assertEqual(recv_line(b), "l2")
        self.assertEqual(recv_line(b), "l3")
        a.close()
        b.close()

    def test_fragmented_chunked_arrival(self):
        a, b = socket.socketpair()
        text = "STEP2|" + "A1B2C3D4E5F6078" * 100
        full = (text + "\n").encode()

        def sender():
            for piece in (full[i:i + 7] for i in range(0, len(full), 7)):
                a.sendall(piece)
                time.sleep(0.001)

        t = threading.Thread(target=sender)
        t.start()
        self.assertEqual(recv_line(b), text)
        t.join()
        a.close()
        b.close()

    def test_binary_safe_split_on_received_bytes(self):
        a, b = socket.socketpair()
        a.sendall(b"A" * 5000)
        time.sleep(0.05)
        a.sendall(b"B" * 5000 + b"\n")
        self.assertEqual(recv_line(b), "A" * 5000 + "B" * 5000)
        a.close()
        b.close()

    def test_clean_close_returns_none(self):
        a, b = socket.socketpair()
        a.close()
        self.assertIsNone(recv_line(b))
        b.close()

    def test_mid_line_close_raises(self):
        a, b = socket.socketpair()
        a.sendall(b"half line")
        a.close()
        with self.assertRaises(ConnectionError):
            recv_line(b)
        b.close()

    def test_line_length_guard(self):
        a, b = socket.socketpair()
        sender = threading.Thread(target=lambda: a.sendall(b"X" * (MAX_LINE + 1)))
        sender.daemon = True
        sender.start()
        with self.assertRaises(ConnectionError):
            recv_line(b)
        a.close()
        b.close()


class TestTwoThreadsOnLocalhost(unittest.TestCase):
    def test_full_duplex_chat_exchange(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        got_client = []
        got_server = []

        def server_side():
            conn, _ = server.accept()
            send_line(conn, "STEP2|hello from server")
            got_server.append(recv_line(conn))
            conn.close()
            server.close()

        t = threading.Thread(target=server_side)
        t.start()
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        got_client.append(recv_line(client))
        send_line(client, "STEP4|8263914")
        t.join(timeout=5)
        self.assertEqual(got_client, ["STEP2|hello from server"])
        self.assertEqual(got_server, ["STEP4|8263914"])
        client.close()


if __name__ == "__main__":
    unittest.main()
