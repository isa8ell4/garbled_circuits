from cryptography.hazmat.primitives.asymmetric import rsa
import struct, socket
from yao2 import WireLabel
import pickle


# TODO: change communication protocol to send a wirelabel where the wire id is also attached

def send_circuit(sock: socket.socket, obj) -> None:
    payload = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    header = struct.pack("!I", len(payload))  # 4-byte big-endian length
    sock.sendall(header + payload)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        buf += chunk
    return buf

def recv_circuit(sock: socket.socket):
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    payload = recv_exact(sock, length)
    return pickle.loads(payload)    

def pack_wirelabel(label:WireLabel) -> bytes:
    # return (label.key << 1) | int_to_bytes(label.pbit)
    return label.key + bytes([label.pbit])

def unpack_wirelabel(data: bytes) -> WireLabel:
    # pbit = b&1
    # key = b<<1
    # return WireLabel(key, pbit)
    key = data[:-1]
    pbit = data[-1]
    return WireLabel(key, pbit)


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

def wires_to_inputs(wire_ids: list[int], bid: int) -> dict:
    """
    map inputs to intended wires. small wire ids get MSB, greater wire ids get LSB
    
    :param wire_ids: Description
    :type wire_ids: list[int]
    :param bid: Description
    :type bid: int

    return: dict (wire id: binary input)
    """
    
    wires_to_inputs = {}
    wire_ids.sort(reverse=True)


    bid_bits = int_to_bits(bid)
    print(f'converted {bid} (int) to {bid_bits} (binary)')

    for i, bit in enumerate(bid_bits):
        if bit == 1:
            break
    
    valuable_bits = bid_bits[i:]

    if len(valuable_bits) > len(wire_ids):
        raise ValueError(
            f"Too many valuable bits ({len(valuable_bits)}) "
            f"for available wire IDs ({len(wire_ids)})"
        )
    
    bid_bits.reverse()
    for index, wire_id in enumerate(wire_ids):
        wires_to_inputs[wire_id] = bid_bits[index]

    print(f'wires to inputs: {wires_to_inputs}')
    return wires_to_inputs



    
