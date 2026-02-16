import socket, ssl, struct, json, random, secrets
from coms import *
from tester import ot_key
import hashlib
from yao2 import Wire, WireLabel
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
# from yao2 import GarbledGate

class Bob: # server
    def __init__(self, config_json, wealth, port=8089, host='localhost', msgs = None):
        self.config_json = config_json
        self.wealth = wealth

        self.circuit_inputs = {} # wire id: wire input/label, both alice + bob inputs
        self.garbled_circuit = {}
        # self.alice_inputs = {}

        self.port = port 
        self.host = host
        self.connection = None
        self.address = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.msgs = [] if msgs is None else msgs

    
    def start(self):
        # create socket connection here
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        # socket connection
        self.connection, self.address = self.socket.accept()

        # get my inputs from alice using oblivious transfer
        print(f'\ninputs from alice using OT\n')
        self.get_bob_inputs()

        # get alice inputs + circuit
        print(f'\nalice sents her inputs\n')
        alice_inputs = self.get_alice_inputs()
        print(f'alice inputs are: {alice_inputs}')

        print(f'circuit inputs: {self.circuit_inputs}')

        print(f'\nreceive garbled circuit\n')
        self.get_garbled_circuit()

        # evaluate
        print(f'\nevaluate garbled circuit\n')
        output_encrypted = self.evaluate_circuit(garbled_tables=self.garbled_circuit, 
                              circuit_inputs=self.circuit_inputs)
        
        # send results to alice
        print(f'\nsend encrypted results to alice\n')
        self.send_encrypted_result(output_encrypted)

    def send_encrypted_result(self, output_encrypted:WireLabel):
        """
        send alice encrypted result
        
        :param output_encrypted: Description
        :type output_encrypted: WireLabel
        """
        wire_label_bytes = pack_wirelabel(output_encrypted)
        send_bytes(self.connection, wire_label_bytes)


    def evaluate_circuit(self, garbled_tables:dict, circuit_inputs:dict):
        """
        Use Kahn's algorithm to go through topological evalution of gates
        
        :param self: Description
        :param garbled_tables: dictionary of gate_ids and encrypted outputs
        :param circuit_inputs: dictionary of wire_ids and their values (either l0 or l1)
        """
        
        ### build necessary lists and dicts

        input_wires = self.config_json["circuits"][0]["bob"]
        input_wires.extend(self.config_json["circuits"][0]["alice"])

        ready_queue = [] # list of gates ready for evaluation, input wire labels are found
        remaining_inputs = {} # gate_id: count of missing inputs
        all_gate_inputs = {} # gate_id: ids of input wires

        all_wires = [gate["id"] for gate in self.config_json["circuits"][0]["gates"]]
        all_wires.extend(input_wires)
        # dependents = dict.fromkeys(all_wires, []) # gate_id: list of gates that use this wire
        dependents = {w: [] for w in all_wires}


        wire_values = dict.fromkeys(all_wires, None) # values of wires when solved
        for input_wire, value in circuit_inputs.items():
            wire_values[input_wire] = value

        for gate in self.config_json["circuits"][0]["gates"]: # go through all valid gates

            gate_id = gate["id"]
            gate_inputs = gate["in"]
            gate_type = gate["type"]
            # print(f'gate_type: {gate_type}')
            print(f'gate {gate_id} | {gate_type}')

            all_gate_inputs[gate_id] = gate_inputs
            
            for wire_id in gate_inputs:
                dependents[wire_id].append(gate_id)

            common_elements = list(set(input_wires).intersection(gate_inputs))
            print(f'common elements: {common_elements}')

            if gate_type == "NOT" or gate_type == "INV":
                missing_inputs = 1 - len(common_elements)
            else: 
                missing_inputs = 2 - len(common_elements)

            remaining_inputs[gate_id] = missing_inputs

            if missing_inputs == 0:
                ready_queue.append(gate_id)
        
        print(f'ready_queue: {ready_queue}')

        ### evaluate gates in topological order
        while ready_queue:
            gate_id = ready_queue.pop(0)
            

            print(f'\nprocessing gate {gate_id}')

            # get inputs
            gate_input_ids = all_gate_inputs[gate_id]
            gate_inputs = {}
            for id in gate_input_ids:
                label = wire_values[id]
                gate_inputs[id] = label
                if label == None: 
                    raise ValueError(f'input wire {id} for gate {gate_id} is None')

            gate_output_label = self.eval_gate(gate_id, gate_inputs, garbled_tables[gate_id])
            wire_values[gate_id] = gate_output_label

            for g in dependents[gate_id]:
                remaining_inputs[g] -=1
                if remaining_inputs[g] == 0:
                    ready_queue.append(g)

        # get output
        out_wire_id = self.config_json["circuits"][0]["out"][0]
        # print(out_wire_id)
        out_wire_label = wire_values[out_wire_id]
        # print(out)
        return out_wire_label

    
    def eval_gate(self, gate_id:int, gate_inputs:dict, possible_outputs:list):
        """
        evaluate gate based on wire_input values
        
        :param self: Description
        
        :param gate_inputs: dictionary of wire ids and their values
        :type gate_inputs: dict
        :param possible_outputs: list (len 2 or 4) possible encrypted outputs
        """
        print("gate", gate_id)
        print(f'inputs: {gate_inputs}')
        print(f'possible outputs: {possible_outputs}')
        # print(f'gate_inptus: {gate_inputs}')
        # print(f'gate_type: {gate_type}')


        if len(list(gate_inputs.values())) == 1: # NOT or INV gate
            wire_input = list(gate_inputs.values())[0]
            index = self.get_index_pbit_not(pbit=wire_input.pbit)
            ciphertext = possible_outputs[index]
            out = self.garble_decrypt_not(wire=wire_input, ciphertext=ciphertext, gate_id=gate_id)
        else: 
            # wire0 = list(gate_inputs.values())[0]
            # wire1 = list(gate_inputs.values())[1]
            # index=self.get_index_pbits(pbit0=wire0.pbit, pbit1=wire1.pbit)
            # ciphertext = possible_outputs[index]
            # out = self.garble_decrypt(wire0=wire0, wire1=wire1, ciphertext=ciphertext, gate_id=gate_id)
            # gate_inputs is {wire_id: WireLabel, wire_id: WireLabel}
            (wid0, wire0), (wid1, wire1) = sorted(gate_inputs.items(), key=lambda kv: kv[0])

            index = self.get_index_pbits(wire0.pbit, wire1.pbit)
            ciphertext = possible_outputs[index]
            

            out = self.garble_decrypt(wire0, wire1, ciphertext, gate_id)

        print(f'out decrypted: {out}')
        return out

    def get_index_pbits(self, pbit0:int, pbit1:int):
        if pbit0==0 and pbit1==0:
            return 0
        elif pbit0==0 and pbit1==1:
            return 1
        elif pbit0==1 and pbit1==0:
            return 2
        elif pbit0==1 and pbit1==1:
            return 3
        else: 
            raise ValueError(f'pbit(s) is not 0 or 1, but {pbit0} and {pbit1}')
        
    def get_index_pbit_not(self, pbit:int):
        if pbit==0:
            return 0
        elif pbit==1:
            return 1
        else: 
            raise ValueError(f'pbit is not 0 or 1, but {pbit}')

    def H(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


    def derive_pad(self, k0, k1, gate_id, length):
        digest = self.H(k0 + k1 + gate_id.to_bytes(4, 'big'))
        return digest[:length]

    def garble_decrypt(self, wire0: WireLabel, wire1: WireLabel, ciphertext, gate_id: int):
        pad = self.derive_pad(wire0.key, wire1.key, gate_id, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, pad))

        # Unpack: id (4 bytes) + key (16 bytes) + pbit (1 byte)
        id_val = int.from_bytes(plaintext[:4], 'big')
        key = plaintext[4:-1]
        pbit = plaintext[-1]
        return WireLabel(id=id_val, key=key, pbit=pbit)
    
    def derive_pad_not(self, k0, gate_id, length):
        digest = self.H(k0 + gate_id.to_bytes(4, 'big'))
        return digest[:length]

    def garble_decrypt_not(self, wire: WireLabel, ciphertext, gate_id: int):
        pad = self.derive_pad_not(wire.key, gate_id, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, pad))

        # Unpack: id (4 bytes) + key (16 bytes) + pbit (1 byte)
        id_val = int.from_bytes(plaintext[:4], 'big')
        key = plaintext[4:-1]
        pbit = plaintext[-1]
        return WireLabel(id=id_val, key=key, pbit=pbit)

    def get_garbled_circuit(self):
        self.garbled_circuit = recv_circuit(self.connection)
        print(f'recieved garbled circuit: {self.garbled_circuit}')

    def get_alice_inputs(self):
        """
        get alice's wire inputs. must be received with smallest wire to largest wire

        :param self: Description
        """
        alice_input_ids = self.config_json['circuits'][0]['alice']
        alice_input_ids.sort()  # Ensure same order as sender
        print(f'alice input ids: {alice_input_ids}')
        
        sock = self.connection
        alice_inputs = []
        
        for wire_id in alice_input_ids:
            # Receive bytes directly (not int)
            wire_label_bytes = recv_bytes(sock)
            wire_label = unpack_wirelabel(wire_label_bytes)
            alice_inputs.append(wire_label)

        print(f'alice input ids: {alice_input_ids}')
        for i, wire_id in enumerate(alice_input_ids):
            input_label = alice_inputs[i]
            print(f'wire id: {wire_id}')
            print(f'wirelabel: {input_label}')
            
            # Store the wirelabel
            self.circuit_inputs[wire_id] = input_label

            # Validate that the wirelabel's id matches the expected wire id
            if input_label.id != wire_id:
                raise ValueError(
                    f'Wire ID mismatch: expected {wire_id}, '
                    f'but wirelabel has id {input_label.id}'
                )

        return alice_inputs


    def get_bob_inputs(self):

        """
        use oblivious transfer to get inputs for both wires 
        
        :param self: Description
        """
        # identify wires
        # print(self.config_json)
        input_wire_ids = self.config_json["circuits"][0]["bob"]
        # print(f'input_wire_ids: {input_wire_ids}')

        # get decision bits for both wires
        # wealth_bits = int_to_bits(self.wealth)

        # map wire to binary input
        wire_inputs = wires_to_inputs(wire_ids=input_wire_ids, bid=self.wealth)
        wire_inputs_sorted = dict(sorted(wire_inputs.items()))

        # print(f'bob wealth bits: {wealth_bits}')
    

        # get inputs for each input wire using oblivious transfer
        # go from smallest wire id to largest wire id
        for wire_id, bit in wire_inputs_sorted.items():
        # for i, input_wire_id in enumerate(input_wire_ids):
            print(f'OT inputs for wire {wire_id}')
            self.circuit_inputs[wire_id] = self.oblivious_transfer_bob(bit)


    def oblivious_transfer_bob(self, input_bit: int):
        sock = self.connection

        # Receive public key and random numbers from alice
        e = recv_int(sock)
        n = recv_int(sock)
        x0 = recv_int(sock)
        x1 = recv_int(sock)

        # Generate k
        k = secrets.randbelow(n - 1) + 1

        # Compute v
        if input_bit == 0:
            v = (x0 + pow(k, e, n)) % n
        elif input_bit == 1:
            v = (x1 + pow(k, e, n)) % n
        else:
            raise ValueError('decision bit is not 0 or 1')

        send_int(sock, v)

        # Receive encrypted labels
        m0_tick_bytes = recv_bytes(sock)
        m1_tick_bytes = recv_bytes(sock)

        # Derive encryption key from k
        k_bytes = int_to_bytes(k)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ot-encryption',
            backend=default_backend()
        )
        encryption_key = kdf.derive(k_bytes)

        # Decrypt the chosen message
        if input_bit == 0:
            m_encrypted = m0_tick_bytes
        else:
            m_encrypted = m1_tick_bytes

        # XOR decryption
        m_bytes = bytes(a ^ b for a, b in zip(m_encrypted, encryption_key[:len(m_encrypted)]))
        
        m_unpacked = unpack_wirelabel(m_bytes)
        print(f'received: {m_unpacked}')
        
        return m_unpacked

    # def oblivious_transfer_bob(self, input_bit:int):
    #     """
    #     Docstring for oblivious_transfer_bob
        
    #     :param self: Description
    #     :param input_wire_id: id of wire
    #     :type input_wire_id: int
    #     :param input_bit: decision bit, 0 or 1
    #     :type input_bit: int
    #     """
    #     sock = self.connection


    #     # get public key and random numbers from alice
    #     e = recv_int(sock)
    #     n = recv_int(sock)
    #     x0 = recv_int(sock)
    #     x1 = recv_int(sock)
    #     # print(f'received e,n,x0,x1')
    #     # e, n = self.recv_pub_key(connection)
    #     # x0, x1 = self.recv_random_numbers(connection)

    #     # print(f'e: {e}\nn: {n}\nx0: {x0}\nx1: {x1}')


    #     # generate k 
    #     # k = secrets.randbelow(n)
    #     k = secrets.randbelow(n - 1) + 1   # 1..n-1 | 0 is not allowed

    #     # print(f'k: {k}')
    #     # print(f'input_bit: {input_bit == 0}')
    #     # compute v
    #     if input_bit == 0: 
    #         v = (x0 + pow(k, e, n)) % n
    #     elif input_bit == 1: 
    #         v = (x1 + pow(k, e, n)) % n
    #     else: 
    #         raise ValueError(f'decision bit is not 0 or 1')
    #     # print(f'v: {v}')
    #     # send v #TODO getting stuck here
    #     send_int(sock, v)

    #     # receive m0_tick and m1_tick
    #     m0_tick = recv_int(sock)
    #     m1_tick = recv_int(sock)
    #     # print(f'received m0_tick and m1_tick')

    #     if input_bit == 0: 
    #         m = (m0_tick -k) % n
    #     elif input_bit ==1:
    #         m = (m1_tick -k) % n

    #     m_unpacked = unpack_wirelabel(int_to_bytes(m))

    #     print(f'received: {m_unpacked}')
        
    #     return m_unpacked
        
                