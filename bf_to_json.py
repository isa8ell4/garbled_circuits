import json
from pathlib import Path


"""
Purpose: convert Bristol Format (old, not Bristol Fashion) to json used for garbled circuit protocol
Link: https://nigelsmart.github.io/MPC-Circuits/old-circuits.html
"""

txt_filepath = f'C:/Users/aisab/Documents/Thesis/garbled_circuits/ex2_garbled_circuit/configs/comparator_32bit_unsigned_lt.txt'
json_filepath = f'C:/Users/aisab/Documents/Thesis/garbled_circuits/ex2_garbled_circuit/configs/comparator_32bit_unsigned_lt.json'

class Gate: 
    def __init__(self, line:str):
        self.line = line
        self.id, self.type, self.inputs = self.create_gate()

    def create_gate(self):
        info_list = self.line.split()
        num_inputs, num_outputs = map(int, info_list[0:2])
        inputs = info_list[2:2+num_inputs]
        id = info_list[2+num_inputs]
        gate_type = info_list[-1]
        return id, gate_type, inputs
    def __str__(self):
        return f'{self.id} | {self.type} | {self.inputs}'


with open(txt_filepath, 'r') as f:
    lines_list = f.readlines()

# print(lines_list)
# print(lines_list[0])

num_gates, num_wires = map(int, lines_list[0].split())
n1, n2, n3 = map(int, lines_list[1].split())

json_dict = {}
json_dict['name'] = Path(txt_filepath).name
json_circuit = {}
json_circuit['id'] = Path(txt_filepath).name
json_circuit['alice'] = list(range(0,n1))
print(n1, n2)
json_circuit['bob'] = list(range(n1, n2+n1))

json_gates = []
largest_gate_id = 0
for line in lines_list[3:]:

    if not line.strip(): # empty or only whitespace
        break

    gate_dict = {}
    gate = Gate(line)
    gate_dict['id'] = gate.id
    gate_dict['type'] = gate.type
    gate_dict['in'] = gate.inputs

    json_gates.append(gate_dict)
    # print(gate)

    if int(gate.id) > largest_gate_id:
        largest_gate_id = int(gate.id)


json_circuit['out'] = largest_gate_id
json_circuit['gates'] = [json_gates]
json_dict["circuits"] = [json_circuit]

json_string = json.dumps(json_dict)
# print(json_string)
with open(json_filepath, 'w') as json_file:
    json.dump(json_dict, json_file, indent=3)