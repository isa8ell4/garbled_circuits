import socket, ssl, struct, json, random, secrets
from cryptography.hazmat.primitives import serialization
from yao2 import GarbledCircuit, Wire, WireLabel
from cryptography.hazmat.primitives.asymmetric import rsa
from coms import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class Alice: 
    def __init__(self, config_json, wealth, port=8089, host='localhost', msgs = None, circuit=None):
        self.config_json = config_json
        self.wealth = wealth
        self.port = port
        self.host = host
        self.msgs = [] if msgs is None else msgs
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.circuit = circuit
        self.garbled_circuit = None

    def start(self):

        # create + garble circuit
        print(f'create garbled circuit')
        self.garbled_circuit = self.garble_circuit()
        

        # create connection to Bob
        self.socket.connect((self.host, self.port))

        # do oblivious transfer protocol with bob to send bob his inputs
        print(f'\nsend bob inputs through oblivious transfer\n')
        self.send_bob_inputs()

        # send alice (self) inputs
        print(f'\nsend alice inputs\n')
        self.send_alice_inputs()

        # send garbled circuit
        print(f'\nsend garbled circuit\n')
        print(f'garbled circuit to send: \n{self.garbled_circuit.garbled_circuit}')

        print(f'valid wires and wirelabels')
        for wire in list(self.garbled_circuit.wires.values()):
            print(wire)

        
        self.send_garbled_circuit()

        # wait for evaluation
        print(f'\nreceive evaluation\n')
        result_wire_label = self.receive_encrypted_result()
        print(f'\ndecrypt results\n')
        result = self.decrypt_output(result_wire_label, self.config_json["circuits"][0]["out"][0])
        print(f'result: {result}')

        if result == 0:
            print(f'Bob is richer')
        elif result == 1:
            print(f'Alice is richer')

        self.socket.shutdown(socket.SHUT_WR)   # tell Bob we're done sending
        # print("[Alice] Sent and shut down write end.")
        self.socket.close()
        print("[Alice] Closed socket.")


    def decrypt_output(self, wire_label:WireLabel, output_wire_id:int):
        """
        map wirelabel result back to 0 or 1 to show if alice or bob won/who is richer
        
        :param self: Description
        :param wire_label: Description
        :type wire_label: WireLabel
        :param output_wire_id: Description
        :type output_wire_id: int
        """
        gate = [gate for gate in self.garbled_circuit.garbled_gates if gate.id == output_wire_id][0]
        print(f'winning wire label: \n {wire_label}')
        print(gate)
        # print(f'garbled table: \n{gate.garbled_table}')
        print(f'wire labels: \n{gate.wires[output_wire_id].l0}, {gate.wires[output_wire_id].l1}')
        if wire_label == gate.wires[output_wire_id].l0:
            return 0
        elif wire_label == gate.wires[output_wire_id].l1:
            return 1


    def receive_encrypted_result(self):
        result_encrypted = recv_bytes(sock=self.socket)
        result_wire_label = unpack_wirelabel(result_encrypted)
        return result_wire_label


    def send_garbled_circuit(self):
        send_circuit(self.socket, self.garbled_circuit.garbled_circuit)

    def garble_circuit(self):
        circuit = GarbledCircuit(config_json=self.config_json['circuits'][0])

        # for gate in circuit.garbled_gates:
        #     print(gate)
        return circuit

    def send_alice_inputs(self):
        """
        send alice's inputs. must be sent in order of smallest wire id to largest wire id
        
        :param self: Description
        """
        # get wire inputs options
        alice_input_ids = self.config_json['circuits'][0]['alice']
        alice_input_ids.sort()

        wire_inputs_binary = wires_to_inputs(wire_ids=alice_input_ids, bid=self.wealth, msb_first=False)
        wire_inputs_binary_sorted = dict(sorted(wire_inputs_binary.items()))
        print(f'wire_inputs_binary_sorted: {wire_inputs_binary_sorted}')

        for wire_id, bit in wire_inputs_binary_sorted.items():
            wire = self.garbled_circuit.wires[wire_id]
            print(f'options for wire {wire_id}:\n0: {wire.l0}\n1: {wire.l1}')
            if bit == 0:
                wire_label_bytes = pack_wirelabel(wire.l0)
                print(f'alice input for wire {wire_id} and input 0 is {wire.l0}')
            elif bit == 1:
                wire_label_bytes = pack_wirelabel(wire.l1)
                print(f'alice input for wire {wire_id} and input 1 is {wire.l1}') 
            else: 
                raise ValueError(f'wealth bit is not 0 or 1')
            
            send_bytes(self.socket, wire_label_bytes)


        
    def send_bob_inputs(self):
        # bob input options
        bob_input_ids = self.config_json['circuits'][0]['bob']

        
        # # for each wire do oblivious transfer
        for id in bob_input_ids:
            print(f'send inputs for wire {id}')
            wire = self.garbled_circuit.wires[id]
            print(f'options for wire {id}: \n0: {wire.l0}\n1: {wire.l1}')
            self.oblivious_transfer_alice(m0=wire.l0, m1=wire.l1)

    def oblivious_transfer_alice(self, m0: WireLabel, m1: WireLabel):
        # Convert wirelabel to bytes
        m0_bytes = pack_wirelabel(m0)
        m1_bytes = pack_wirelabel(m1)

        # Generate RSA key pair
        d = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_numbers = d.private_numbers()
        d_exp = private_numbers.d

        public_key = d.public_key()
        public_numbers = public_key.public_numbers()
        e, n = public_numbers.e, public_numbers.n

        # Send public key and random numbers
        send_int(self.socket, e)
        send_int(self.socket, n)

        x0 = secrets.randbelow(n)
        x1 = secrets.randbelow(n)
        send_int(self.socket, x0)
        send_int(self.socket, x1)

        # Wait for v
        v = recv_int(self.socket)

        # Compute k0 and k1
        k0 = pow((v - x0) % n, d_exp, n)
        k1 = pow((v - x1) % n, d_exp, n)

        # Derive encryption keys - CREATE SEPARATE KDF INSTANCES
        k0_bytes = int_to_bytes(k0)
        k1_bytes = int_to_bytes(k1)
        
        kdf0 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ot-encryption',
            backend=default_backend()
        )
        encryption_key0 = kdf0.derive(k0_bytes)
        
        kdf1 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ot-encryption',
            backend=default_backend()
        )
        encryption_key1 = kdf1.derive(k1_bytes)

        # Encrypt m0 and m1 using XOR
        m0_encrypted = bytes(a ^ b for a, b in zip(m0_bytes, encryption_key0[:len(m0_bytes)]))
        m1_encrypted = bytes(a ^ b for a, b in zip(m1_bytes, encryption_key1[:len(m1_bytes)]))

        # Send encrypted messages
        send_bytes(self.socket, m0_encrypted)
        send_bytes(self.socket, m1_encrypted)
    
    # def oblivious_transfer_alice(self, m0:WireLabel, m1:WireLabel):

    #     # convert wirelabel datatype to an int
    #     m0_packed_bytes = pack_wirelabel(m0)
    #     m1_packed_bytes = pack_wirelabel(m1)

    #     m0_packed_int = bytes_to_int(m0_packed_bytes)
    #     m1_packed_int = bytes_to_int(m1_packed_bytes)

    #     #gen RSA key pair and send pub portion to Bob

    #     # private key
    #     d = rsa.generate_private_key(
    #         public_exponent=65537,
    #         key_size=2048,
    #     )
    #     # priv_bytes = d.private_bytes(
    #     #     encoding=serialization.Encoding.PEM,
    #     #     format=serialization.PrivateFormat.TraditionalOpenSSL,
    #     #     encryption_algorithm=serialization.NoEncryption()
    #     # )
    #     # priv_int = bytes_to_int(priv_bytes)
    #     private_numbers = d.private_numbers()
    #     d_exp = private_numbers.d

    #     public_key = d.public_key()
    #     public_numbers = public_key.public_numbers()
    #     e, n = public_numbers.e, public_numbers.n


    #     # send public key info (e, n) and random numbers x0, x1 (below n)
    #     send_int(self.socket, e)
    #     send_int(self.socket, n)
    #     # self.socket.sendall(int_to_bytes(public_numbers.e))
    #     # self.socket.sendall(int_to_bytes(public_numbers.n))

    #     x0 = secrets.randbelow(n)
    #     x1 = secrets.randbelow(n)
    #     send_int(self.socket, x0)
    #     send_int(self.socket, x1)
    #     # print(f'e: {e}\nn: {n}\nx0: {x0}\nx1: {x1}')
    #     # self.socket.sendall(int_to_bytes(x0))
    #     # self.socket.sendall(int_to_bytes(x1))

    #     # wait for v
    #     v = recv_int(self.socket)
    #     # print(f'received v')

    #     # calc k0, k1, m0_tick, m1_tick

    #     # k0 = pow(v-x0, d_exp, n) # (v-x0)**d % n
    #     k0 = pow((v - x0) % n, d_exp, n)
    #     m0_tick = (m0_packed_int+k0) % n

    #     # k1 = pow(v-x1, d_exp, n) # (v-x1)**d % n
    #     k1 = pow((v - x1) % n, d_exp, n)
    #     m1_tick = (m1_packed_int+k1) % n

    #     send_int(self.socket, m0_tick)
    #     send_int(self.socket, m1_tick)


