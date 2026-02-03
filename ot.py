from cryptography.hazmat.primitives.asymmetric import rsa
import struct
from yao2 import WireLabel

def pack_wirelabel(label:WireLabel):
    # return (label.key << 1) | int_to_bytes(label.pbit)
    return label.key + bytes([label.pbit])

def unpack_wirelabel(data):
    # pbit = b&1
    # key = b<<1
    # return WireLabel(key, pbit)
    key = data[:-1]
    pbit = data[-1]
    return key, pbit


def send_bytes(sock, b: bytes):
    sock.sendall(struct.pack("!I", len(b)) + b)

def recv_bytes(sock) -> bytes:
    header = recvall(sock, 4)
    (n,) = struct.unpack("!I", header)
    return recvall(sock, n)

def recvall(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data += chunk
    return data

def send_int(sock, x: int):
    b = int_to_bytes(x)
    send_bytes(sock, b)

def recv_int(sock) -> int:
    b = recv_bytes(sock)
    return bytes_to_int(b)

def int_to_bytes(num):
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length)

def bytes_to_int(b):
    return int.from_bytes(b)

def int_to_bits(num):
    """returns list of bits in big endian"""
    bits = [int(b) for b in format(num, '08b')]
    return bits

def bits_to_int(bits):
    x = 0
    for b in bits:
        x = (x << 1) | b
    return x