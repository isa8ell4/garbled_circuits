import pickle, random, os
from cryptography.fernet import Fernet


def encrypt(key, data):
    """Encrypt a message.

    Args:
        key: The encryption key.
        data: The message to encrypt.

    Returns:
        The encrypted message as a byte stream.
    """
    f = Fernet(key)
    return f.encrypt(data)


class Wire: 
    def __init__(self, id, l1=None, l2=None):
        self.id = id
        self.l1 = l1
        self.l2 = l2

class GarbledCircuit: 
    def __init__(self, config_json):
        self.config_json = config_json
        self.gates_json = config_json["gates"]
        self.garbled_gates = self.create_garbled_gates()
        self.garbled_circuit = self.create_garbled_circuit()

    def create_garbled_gates(self):
        """creates all garbled gates"""
        garbled_gates = []
        print(f'gates_json: {type(self.gates_json)}\n{self.gates_json}')
        for gate_json in self.gates_json: 
            gate = GarbledGate(gate_json=gate_json)
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
        print('at create garbled circuit')
        garbled_circuit = {}
        circuit_inputs = []
        circuit_inputs.extend(self.config_json["alice"])
        circuit_inputs.extend(self.config_json["bob"])

        # print(f'input wires: {circuit_inputs}')
        # print(f'garbled_gates: {self.garbled_gates}')
        
        org_gates_outputs = self.organize_gates_output()
        # org_gates_inputs = self.organize_gates_inputs()
        for id, gate in org_gates_outputs.items():

            # if id in circuit_inputs: 
            #     pass # might need smth else here

            # gate_inputs = gate.input
            # common = set(gate_inputs) & set(circuit_inputs)

            print(f'gate {gate.id}: \n{gate.table}\n{gate.garbled_table}\n')

            # get output wire label value
            # get all gates with 

            # encrypt output wire label with appropriate inputs 


    
class GarbledGate:
    def __init__(self, gate_json):
        self.id = gate_json["id"]
        self.input = gate_json["in"]  # list of inputs'ID
        self.output = gate_json["id"]  # ID of output
        self.gate_type = gate_json["type"]  # Gate type: OR, AND, ...
        self.table = {} # plain boolean table
        self.garbled_table = {} 

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

        in_0_w = os.urandom(16)
        in_1_w = os.urandom(16)

        in_0_p = random.choice([0,1])
        in_1_p = not in_0_p

        in_0 = (in_0_w, in_0_p)
        in_1 = (in_1_w, in_1_p)

        # print(f'b1: {b1}\nb2: {b2}')
        
        for b1, out in self.table.items():
            if b1==0:
                self.garbled_table[in_0] = out
            if b1==1:
                self.garbled_table[in_1] = out

        # order according to pbits
        sorted_items = sorted(
            self.garbled_table.items(),
            key=lambda item: item[0][1]
        )
        self.garbled_table = dict(sorted_items)

    def create_garbled_gate(self, operator):
        """
        assigns wire labels to inputs and orders using pbits (point-and-permute)
        
        :param self: Description
        """

        self.create_table(operator)

        # input wire labels
        in1_0_w = os.urandom(16)
        in1_1_w = os.urandom(16)
        in2_0_w = os.urandom(16)
        in2_1_w = os.urandom(16)

        # pbits 
        in1_0_p = random.choice([0,1])
        in1_1_p = not in1_0_p
        in2_0_p = random.choice([0,1])
        in2_1_p = not in2_0_p

        # add pbits
        # in1_0 = int(str(in1_0) + str(in1_0_p))
        # in1_1 = int(str(in1_1) + str(in1_1_p))
        # in2_0 = int(str(in2_0) + str(in2_0_p))
        # in2_1 = int(str(in2_1) + str(in2_1_p))
        in1_0 = (in1_0_w, in1_0_p)
        in1_1 = (in1_1_w, in1_1_p)
        in2_0 = (in2_0_w, in2_0_p)
        in2_1 = (in2_1_w, in2_1_p)

        for (b1, b2), out in self.table.items():
            if b1==0 and b2==0:
                self.garbled_table[(in1_0,in2_0)] = out
            if b1==0 and b2 ==1:
                self.garbled_table[(in1_0,in2_1)] = out
            if b1==1 and b2==0:
                self.garbled_table[(in1_1,in2_0)] = out
            if b1==1 and b2 ==1:
                self.garbled_table[(in1_1,in2_1)] = out

        # order according to pbits
        sorted_items = sorted(
            self.garbled_table.items(),
            key=lambda item: item[0][1]
        )

        self.garbled_table = dict(sorted_items)



            
            

    