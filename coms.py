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


def pack_wirelabel(label: WireLabel) -> bytes:
    # Pack: id (4 bytes) + key (16 bytes) + pbit (1 byte) = 21 bytes
    return label.id.to_bytes(4, 'big') + label.key + bytes([label.pbit])

def unpack_wirelabel(data: bytes) -> WireLabel:
    id_val = int.from_bytes(data[:4], 'big')
    key = data[4:-1]
    pbit = data[-1]
    return WireLabel(id=id_val, key=key, pbit=pbit)

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

def int_to_bits(num, msb_first=True, bit_size='08b'):
    """returns list of bits in big endian"""
    bits = [int(b) for b in format(num, bit_size)]
    if msb_first==False:
        bits.reverse()
    return bits

def bits_to_int(bits):
    x = 0
    for b in bits:
        x = (x << 1) | b
    return x

def wires_to_inputs(wire_ids: list[int], bid: int, msb_first=True) -> dict:
    """
    map inputs to intended wires. small wire ids get MSB, greater wire ids get LSB (unless msb_first=false, little endian)
    
    :param wire_ids: Description
    :type wire_ids: list[int]
    :param bid: Description
    :type bid: int
    :param msb_first: big endian
    :type msb_first: bool

    return: dict (wire id: binary input)
    """
    
    wires_to_inputs = {}
    wire_ids.sort(reverse=True)



    bid_bits = int_to_bits(bid, msb_first=msb_first, bit_size='032b')
    print(f'converted {bid} (int) to {bid_bits} (binary)')

    # for i, bit in enumerate(bid_bits):
    #     if bit == 1:
    #         break
    
    # valuable_bits = bid_bits[i:]

    # if len(valuable_bits) > len(wire_ids):
    #     raise ValueError(
    #         f"Too many valuable bits ({len(valuable_bits)}) "
    #         f"for available wire IDs ({len(wire_ids)})"
    #     )
    
    # bid_bits.reverse()

    if len(bid_bits) != len(wire_ids):
        raise ValueError(f'length of bits does not match number of wires')
    

    print(f'wire_ids: {wire_ids}')

    for index, wire_id in enumerate(wire_ids):
        wires_to_inputs[wire_id] = bid_bits[index]

    print(f'wires to inputs: {wires_to_inputs}')
    return wires_to_inputs



    
