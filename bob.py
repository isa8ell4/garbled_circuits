import socket, ssl, struct, json, random, secrets
from coms import *
from tester import ot_key
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
        self.get_bob_inputs()

        # get alice inputs + circuit
        self.get_alice_inputs()
        # print(f'circuit inputs: {self.circuit_inputs}')
        self.get_garbled_circuit()

        # evaluate

        self.evaluate_circuit(garbled_tables=self.garbled_circuit, 
                              circuit_inputs=self.circuit_inputs)


        # publish results 

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
        dependents = dict.fromkeys(all_wires, []) # gate_id: list of gates that use this wire

        wire_values = dict.fromkeys(all_wires, None) # values of wires when solved
        for input_wire, value in circuit_inputs.items():
            wire_values[input_wire] = value

        for gate in self.config_json["circuits"][0]["gates"]: # go through all valid gates

            gate_id = gate["id"]
            gate_inputs = gate["in"]
            gate_type = gate["type"]

            all_gate_inputs[gate_id] = gate_inputs
            
            for wire_id in gate_inputs:
                dependents[wire_id].append(gate_id)

            common_elements = list(set(input_wires).intersection(gate_inputs))

            if gate_type == "NOT":
                missing_inputs = 1 - len(common_elements)
            else: 
                missing_inputs = 2 - len(common_elements)

            remaining_inputs[gate_id] = missing_inputs

            if missing_inputs == 0:
                ready_queue.append(gate_id)
        
        print(f'ready_queue: {ready_queue}')

        ### evaluate gates in topological order
        while ready_queue:
            gate_id = ready_queue.pop()

            print(f'\nprocessing gate {gate_id}')

            # get inputs
            gate_input_ids = all_gate_inputs[gate_id]
            gate_inputs = {}
            for id in gate_input_ids:
                label = wire_values[id]
                gate_inputs[id] = label
                if label == None: 
                    raise ValueError(f'input wire {id} for gate {gate_id} is None')

            gate_output_label = self.eval_gate(gate_inputs, garbled_tables[gate_id])
            wire_values[gate_id] = gate_output_label

            for g in dependents[gate_id]:
                remaining_inputs[g] -=1
                if remaining_inputs[g] == 0:
                    ready_queue.append(g)
    

    def eval_gate(self, gate_inputs:dict, possible_outputs:list):
        """
        evaluate gate based on wire_input values
        
        :param self: Description
        
        :param gate_inputs: dictionary of wire ids and their values
        :type gate_inputs: dict
        :param possible_outputs: list (len 2 or 4) possible encrypted outputs
        """
        print(f'inputs: {gate_inputs}')
        print(f'possible outputs: {possible_outputs}')

    def get_garbled_circuit(self):
        self.garbled_circuit = recv_circuit(self.connection)
        print(f'recieved garbled circuit: {self.garbled_circuit}')

    def get_alice_inputs(self):
        """
       get alice's wire inputs
        
        :param self: Description
        """
        alice_input_ids = self.config_json['circuits'][0]['alice']
        sock = self.connection
        a0_int = recv_int(sock)
        a1_int = recv_int(sock)

        a0 = unpack_wirelabel(int_to_bytes(a0_int))
        a1 = unpack_wirelabel(int_to_bytes(a1_int))
        alice = [a0,a1]

        for i, id in enumerate(alice_input_ids):
            self.circuit_inputs[id] = alice[i]


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

        # print(f'bob wealth bits: {wealth_bits}')
    

        # get inputs for each input wire using oblivious transfer
        for wire_id, bit in wire_inputs.items():
        # for i, input_wire_id in enumerate(input_wire_ids):
            print(f'receive inputs for wire {wire_id}')
            self.circuit_inputs[wire_id] = self.oblivious_transfer_bob(bit)


    def oblivious_transfer_bob(self, input_bit:int):
        """
        Docstring for oblivious_transfer_bob
        
        :param self: Description
        :param input_wire_id: id of wire
        :type input_wire_id: int
        :param input_bit: decision bit, 0 or 1
        :type input_bit: int
        """
        sock = self.connection


        # get public key and random numbers from alice
        e = recv_int(sock)
        n = recv_int(sock)
        x0 = recv_int(sock)
        x1 = recv_int(sock)
        # print(f'received e,n,x0,x1')
        # e, n = self.recv_pub_key(connection)
        # x0, x1 = self.recv_random_numbers(connection)

        # print(f'e: {e}\nn: {n}\nx0: {x0}\nx1: {x1}')


        # generate k 
        # k = secrets.randbelow(n)
        k = secrets.randbelow(n - 1) + 1   # 1..n-1 | 0 is not allowed

        # print(f'k: {k}')
        # print(f'input_bit: {input_bit == 0}')
        # compute v
        if input_bit == 0: 
            v = (x0 + pow(k, e, n)) % n
        elif input_bit == 1: 
            v = (x1 + pow(k, e, n)) % n
        else: 
            raise ValueError(f'decision bit is not 0 or 1')
        # print(f'v: {v}')
        # send v #TODO getting stuck here
        send_int(sock, v)

        # receive m0_tick and m1_tick
        m0_tick = recv_int(sock)
        m1_tick = recv_int(sock)
        print(f'received m0_tick and m1_tick')

        if input_bit == 0: 
            m = (m0_tick -k) % n
        elif input_bit ==1:
            m = (m1_tick -k) % n

        m_unpacked = unpack_wirelabel(int_to_bytes(m))

        print(f'received: {m_unpacked}')
        
        return m_unpacked
        
                