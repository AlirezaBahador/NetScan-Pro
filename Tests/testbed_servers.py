"""
Spins up a handful of local sockets on 127.0.0.1 that mimic real
services (a fake SSH banner, a tiny HTTP server, an echoing UDP
socket) purely so the scanner has something real to find during local
testing / CI. Not part of the shipped package — dev/test only.
"""
import http.server
import socket
import threading
import time


def start_fake_ssh(port=2222):
    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(5)
        while True:
            conn, _ = s.accept()
            conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")
            conn.close()
    threading.Thread(target=serve, daemon=True).start()


def start_http(port=8080):
    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def start_udp_echo(port=9999):
    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", port))
        while True:
            data, addr = s.recvfrom(1024)
            s.sendto(b"ECHO:" + data, addr)
    threading.Thread(target=serve, daemon=True).start()


if __name__ == "__main__":
    start_fake_ssh(2222)
    start_http(8080)
    start_udp_echo(9999)
    print("Testbed services running on 127.0.0.1: TCP 2222 (fake ssh), TCP 8080 (http), UDP 9999 (echo)")
    while True:
        time.sleep(3600)
