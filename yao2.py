import pickle, random, os
from cryptography.fernet import Fernet
import hashlib
from dataclasses import dataclass

# TODO: probably cleaner
@dataclass
class WireLabel:
    key: bytes      # 16 bytes
    pbit: int       # 0 or 1


class Wire: 
    def __init__(self, id, l0=None, l1=None):
        self.id = id
        self.l0 = l0   # (key, pbit) or WireLabel type
        self.l1 = l1
    def __str__(self):
        return f'Wire {self.id} | l0: {self.l0.key}, {self.l0.pbit} | l1: {self.l1.key}, {self.l1.pbit}'


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def derive_pad(k0, k1, gate_id, length):
    digest = H(k0 + k1 + gate_id.to_bytes(4, 'big'))
    return digest[:length]

def garble_encrypt(wire0:WireLabel, wire1:WireLabel, output_label: WireLabel, gate_id:int):
    plaintext = output_label.key + bytes([output_label.pbit])
    pad = derive_pad(wire0.key, wire1.key, gate_id, len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, pad))

def garble_decrypt(wire0, wire1, ciphertext, gate_id):
    pad = derive_pad(wire0[0], wire1[0], gate_id, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, pad))

    key = plaintext[:-1]
    pbit = plaintext[-1]
    return (key, pbit)

def derive_pad_not(k0, gate_id, length):
    digest = H(k0 + gate_id.to_bytes(4, 'big'))
    return digest[:length]

def garble_encrypt_not(wire, output_label:WireLabel, gate_id:int):
    # gate_id = output_label[0]
    plaintext = output_label.key + bytes([output_label.pbit])
    pad = derive_pad_not(wire.key, gate_id, len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, pad))

def garble_decrypt_not(wire,  ciphertext, gate_id):
    pad = derive_pad_not(wire[0], gate_id, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, pad))

    key = plaintext[:-1]
    pbit = plaintext[-1]
    return (key, pbit)


class GarbledCircuit: 
    def __init__(self, config_json):
        self.config_json = config_json
        self.gates_json = config_json["gates"]
        self.wires = self.create_wires() # dict {wire_id : wire object}
        self.garbled_gates = self.create_garbled_gates() # list
        self.garbled_circuit = self.create_garbled_circuit() # dict {id: encrypted output results (table)}


    def create_wires(self):
        wire_ids = []
        wire_ids.extend(self.config_json["alice"])
        wire_ids.extend(self.config_json["bob"])
        for gate in self.config_json["gates"]:
            wire_ids.append(gate["id"])

        wires = {}
        for wire_id in wire_ids:
            p1 = random.choice([0,1])
            p2 = not p1

            if p1 not in [0,1] or p2 not in [0,1]:
                raise ValueError(f'p1= {p1}, p2= {p2}')
            
            wires[wire_id] = Wire(id=wire_id, 
                                  l0=WireLabel(key=os.urandom(16), pbit=p1), 
                                  l1=WireLabel(key=os.urandom(16), pbit=p2))

        return wires 


    def create_garbled_gates(self):
        """
        creates all garbled gates
        
        returns: dict of garbled gates {id: GarbledGate}
        """
        garbled_gates = []
        # print(f'gates_json: {type(self.gates_json)}\n{self.gates_json}')
        for gate_json in self.gates_json: 

            gate_wire_ids = list(gate_json["in"]) + [gate_json["id"]]
            # all_wires.append(gate_json["id"])

            gate_wires = {wire_id: self.wires[wire_id] for wire_id in gate_wire_ids}

                
            gate = GarbledGate(gate_json=gate_json, wires=gate_wires) 
            garbled_gates.append(gate)

        return garbled_gates
    
    # def organize_gates_inputs(self):
    #     """organize and identify gates by their inputs"""
    #     gates_inputs 

    def organize_gates_output(self):
        """organize and identify gates by their outputs, which is also the gate's id"""

        gates_output = {} # id/output : gate
        for gate in self.garbled_gates:
            gates_output[gate.id] = gate
            
        sorted_gates = sorted(
            gates_output.items(),
            key=lambda item: item[0]
        )
        gates_output = dict(sorted_gates)
        return gates_output

    def create_garbled_circuit(self):
        # print('at create garbled circuit')
        garbled_circuit = {}
        circuit_inputs = []
        circuit_inputs.extend(self.config_json["alice"])
        circuit_inputs.extend(self.config_json["bob"])

        # print(f'input wires: {circuit_inputs}')
        # print(f'garbled_gates: {self.garbled_gates}')

        garbled_circuit = {}
        for gate in self.garbled_gates:
            garbled_circuit[gate.id] = gate.garbled_table

        return garbled_circuit
 
class GarbledGate:
    def __init__(self, gate_json, wires):
        self.id = gate_json["id"]
        self.input = gate_json["in"]  # list of inputs'ID
        self.output = gate_json["id"]  # ID of output
        self.gate_type = gate_json["type"]  # Gate type: OR, AND, ...
        self.table = {} # plain boolean table
        self.garbled_table = {} 
        self.wires = wires # dict of wires with their labels

        # Create the garbled table according to the gate type
        switch = {
            "OR": lambda b1, b2: b1 or b2,
            "AND": lambda b1, b2: b1 and b2,
            "XOR": lambda b1, b2: b1 ^ b2,
            "NOR": lambda b1, b2: not (b1 or b2),
            "NAND": lambda b1, b2: not (b1 and b2),
            "NOT": lambda b1: not b1,
            "XNOR": lambda b1, b2: not (b1 ^ b2)
        }

        # operator = switch[self.gate_type]
        # self.create_table(operator)

        # NOT gate is a special case since it has only one input
        if (self.gate_type == "NOT"):
            self.create_garbled_not_gate() 
        else:
            operator = switch[self.gate_type]
            self.create_garbled_gate(operator)


    def __str__(self):
        return f"Gate {self.id} | {self.gate_type}"
            
    def create_table(self, operator):
        for in1 in [0,1]:
            for in2 in [0,1]:

                output = int(operator(in1,in2))
                self.table[(in1, in2)] = output
    
    def create_garbled_not_gate(self):

        # establish regular table
        for input in [0,1]:
            if input == 0:
                self.table[input] = 1
            if input == 1:
                self.table[input] = 0

        # get wire labels 
        in_ids = list(self.input)
        in_ids.sort()
        if len(in_ids) != 1:
            raise ValueError(f"Expected 1-input gate, got inputs={in_ids}")

        w_in1 = self.wires[in_ids[0]]
        # w_in2 = self.wires[in_ids[1]]
        w_out = self.wires[self.id]

        in1 = {0: w_in1.l0, 1: w_in1.l1}
        # in2 = {0: w_in2.l0, 1: w_in2.l1}
        outL = {0: w_out.l0, 1: w_out.l1}

        table2 = [None] * 2

        for b1, out_bit in self.table.items():
            wire0 = in1[b1]
            # wire1 = in2[b2]
            out_label = outL[out_bit]

            # row = (wire0.pbit << 1)    # if tuple use wire0[1]
            table2[wire0.pbit] = garble_encrypt_not(wire=wire0, output_label=out_label, gate_id=self.id)

        self.garbled_table = table2

    def create_garbled_gate(self, operator):
        """
        assigns wire labels to inputs and orders using pbits (point-and-permute)
        
        :param self: Description
        """

        self.create_table(operator)

        # get wire labels 
        in_ids = list(self.input)
        in_ids.sort()
        # print(f'create garbled gate for {self.id}, possible ')
        if len(in_ids) != 2:
            print(self)
            raise ValueError(f"Expected 2-input gate, got inputs={in_ids}")

        w_in1 = self.wires[in_ids[0]]
        w_in2 = self.wires[in_ids[1]]
        w_out = self.wires[self.id]

        in1 = {0: w_in1.l0, 1: w_in1.l1}
        in2 = {0: w_in2.l0, 1: w_in2.l1}
        outL = {0: w_out.l0, 1: w_out.l1}

        # # build garbled table 

        table4 = [None] * 4

        for (b1, b2), out_bit in self.table.items():
            wire0 = in1[b1]
            wire1 = in2[b2]
            out_label = outL[out_bit]

            row = (wire0.pbit << 1) | wire1.pbit   # if tuple use wire0[1]
            table4[row] = garble_encrypt(wire0=wire0, wire1=wire1, output_label=out_label, gate_id=self.id)

        self.garbled_table = table4





            
            

    