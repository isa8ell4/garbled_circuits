import socket, ssl, struct, json, random, secrets
from ot import *
from tester import ot_key

class Bob: # server
    def __init__(self, config_json, wealth, port=8089, host='localhost', msgs = None):
        self.config_json = config_json
        self.wealth = wealth

        self.circuit_inputs = {} # wire id: wire input/label, both alice + bob inputs
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
        print(f'circuit inputs: {self.circuit_inputs}')

        # evaluate


        # publish results 



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
        
                