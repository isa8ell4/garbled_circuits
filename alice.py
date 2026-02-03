import socket, ssl, struct, json, random, secrets
from cryptography.hazmat.primitives import serialization
from yao2 import GarbledCircuit, Wire, WireLabel
from cryptography.hazmat.primitives.asymmetric import rsa
from ot import *

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
        print(f'send bob inputs through oblivious transfer')
        self.send_bob_inputs()

        # send alice (self) inputs
        self.send_alice_inputs()

        # send garbled circuit

        # wait for evaluation

        # print results and shut down

        # self.socket.sendall(b'hello')

        


        # self.socket.shutdown(socket.SHUT_WR)   # tell Bob we're done sending
        # print("[Alice] Sent and shut down write end.")
        # self.socket.close()
        print("[Alice] Closed socket.")

    def garble_circuit(self):
        circuit = GarbledCircuit(config_json=self.config_json['circuits'][0])

        # for gate in circuit.garbled_gates:
        #     print(gate)
        return circuit

    def send_alice_inputs(self):


        # turn input into bits
        # wealth_bits = int_to_bits(self.wealth)

        # print(f'wealth type: {wealth_bits} | {type(wealth_bits)}')

        # get wire inputs options
        alice_input_ids = self.config_json['circuits'][0]['alice']

        wire_inputs = wires_to_inputs(wire_ids=alice_input_ids, bid=self.wealth)

        for wire_id, bit in wire_inputs.items():
            wire = self.garbled_circuit.wires[wire_id]
            if bit == 0:
                wire_label_bytes = pack_wirelabel(wire.l0)
                print(f'sending alice input {wire.l0}')
            elif bit == 1:
                wire_label_bytes = pack_wirelabel(wire.l1)
                print(f'sending alice input {wire.l1}') 
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
            print(f'options for wire {id}: \n{wire.l0}\n{wire.l1}')
            self.oblivious_transfer_alice(m0=wire.l0, m1=wire.l1)

        
    
    def oblivious_transfer_alice(self, m0:WireLabel, m1:WireLabel):

        # convert wirelabel datatype to an int
        m0_packed_bytes = pack_wirelabel(m0)
        m1_packed_bytes = pack_wirelabel(m1)

        m0_packed_int = bytes_to_int(m0_packed_bytes)
        m1_packed_int = bytes_to_int(m1_packed_bytes)

        #gen RSA key pair and send pub portion to Bob

        # private key
        d = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # priv_bytes = d.private_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PrivateFormat.TraditionalOpenSSL,
        #     encryption_algorithm=serialization.NoEncryption()
        # )
        # priv_int = bytes_to_int(priv_bytes)
        private_numbers = d.private_numbers()
        d_exp = private_numbers.d

        public_key = d.public_key()
        public_numbers = public_key.public_numbers()
        e, n = public_numbers.e, public_numbers.n


        # send public key info (e, n) and random numbers x0, x1 (below n)
        send_int(self.socket, e)
        send_int(self.socket, n)
        # self.socket.sendall(int_to_bytes(public_numbers.e))
        # self.socket.sendall(int_to_bytes(public_numbers.n))

        x0 = secrets.randbelow(n)
        x1 = secrets.randbelow(n)
        send_int(self.socket, x0)
        send_int(self.socket, x1)
        # print(f'e: {e}\nn: {n}\nx0: {x0}\nx1: {x1}')
        # self.socket.sendall(int_to_bytes(x0))
        # self.socket.sendall(int_to_bytes(x1))

        # wait for v
        v = recv_int(self.socket)
        # print(f'received v')

        # calc k0, k1, m0_tick, m1_tick

        # k0 = pow(v-x0, d_exp, n) # (v-x0)**d % n
        k0 = pow((v - x0) % n, d_exp, n)
        m0_tick = (m0_packed_int+k0) % n

        # k1 = pow(v-x1, d_exp, n) # (v-x1)**d % n
        k1 = pow((v - x1) % n, d_exp, n)
        m1_tick = (m1_packed_int+k1) % n

        send_int(self.socket, m0_tick)
        send_int(self.socket, m1_tick)


