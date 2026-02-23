import sys, json
from yao2 import Circuit
from coms import wires_to_inputs

def eval_gate(gate_inputs:list, gate_type:str):
    """
    evaluate gate based on wire_input values
    
    :param self: Description
    
    :param gate_inputs: dictionary of wire ids and their values
    :type gate_inputs: dict
    :param possible_outputs: list (len 2 or 4) possible encrypted outputs
    # """

    switch = {
        "OR": lambda b1, b2: b1 or b2,
        "AND": lambda b1, b2: b1 and b2,
        "XOR": lambda b1, b2: b1 ^ b2,
        "NOR": lambda b1, b2: not (b1 or b2),
        "NAND": lambda b1, b2: not (b1 and b2),
        "NOT": lambda b1: not b1,
        "INV": lambda b1: not b1,
        "XNOR": lambda b1, b2: not (b1 ^ b2)
    }

    # print(gate_type)

    operator = switch[gate_type]
    if gate_type == "INV" or gate_type == "NOT":
        out = int(operator(gate_inputs[0]))
    else: 
        out = int(operator(gate_inputs[0], gate_inputs[1]))

    return out

def evaluate_circuit(config_json: dict, circuit_inputs: dict):
    # convert inputs

    # go through every wire
    """
    Use Kahn's algorithm to go through topological evalution of gates
    
    :param self: Description
    :param garbled_tables: dictionary of gate_ids and encrypted outputs
    :param circuit_inputs: dictionary of wire_ids and their values (either l0 or l1)
    """
    
    ### build necessary lists and dicts

    input_wires = list(config_json["circuits"][0]["bob"]) + list(config_json["circuits"][0]["alice"])

    ready_queue = [] # list of gates ready for evaluation, input wire labels are found
    remaining_inputs = {} # gate_id: count of missing inputs
    all_gate_inputs = {} # gate_id: ids of input wires
    types = {} #gate id : gate_type

    all_wires = [gate["id"] for gate in config_json["circuits"][0]["gates"]]
    all_wires.extend(input_wires)
    # dependents = dict.fromkeys(all_wires, []) # gate_id: list of gates that use this wire
    dependents = {w: [] for w in all_wires}


    wire_values = dict.fromkeys(all_wires, None) # values of wires when solved
    for input_wire, value in circuit_inputs.items():
        wire_values[input_wire] = value

    for gate in config_json["circuits"][0]["gates"]: # go through all valid gates

        gate_id = gate["id"]
        gate_inputs = gate["in"]
        gate_type = gate["type"]
        # print(f'gate_type: {gate_type}')
        # print(f'gate {gate_id} | {gate_type}')

        types[gate_id] = gate_type

        all_gate_inputs[gate_id] = gate_inputs
        
        for wire_id in gate_inputs:
            dependents[wire_id].append(gate_id)

        common_elements = list(set(input_wires).intersection(gate_inputs))
        # print(f'common elements: {common_elements}')

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
        gate_type = types[gate_id]

        # print(f'processing gate {gate_id}')

        # get inputs
        gate_input_ids = all_gate_inputs[gate_id]
        gate_inputs = []
        for id in gate_input_ids:
            label = wire_values[id]
            gate_inputs.append(label)
            if label == None: 
                raise ValueError(f'input wire {id} for gate {gate_id} is None')

        gate_output = eval_gate(gate_inputs=gate_inputs, gate_type=gate_type)
        wire_values[gate_id] = gate_output

        for g in dependents[gate_id]:
            remaining_inputs[g] -=1
            if remaining_inputs[g] == 0:
                ready_queue.append(g)

    # get output
    out_wire_id = config_json["circuits"][0]["out"][0]
    # print(out_wire_id)
    out_wire_label = wire_values[out_wire_id]
    # print(out)
    return out_wire_label

if __name__ == "__main__":

    # inputs
    json_path = f'C:/Users/aisab/Documents/Thesis/garbled_circuits/ex2_garbled_circuit/configs/comparator_32bit_unsigned_lt.json'
    alice_wealth = 3
    bob_wealth = 2

    with open(json_path, "r") as f:
        data = json.load(f)

    # convert inputs to binary
    alice_inputs = wires_to_inputs(wire_ids=data["circuits"][0]["alice"], bid=alice_wealth, msb_first=True)
    bob_inputs = wires_to_inputs(wire_ids=data["circuits"][0]["bob"], bid=bob_wealth, msb_first=True)
    
    print(f'alice inputs: \n{alice_inputs}')
    print(f'bob inputs: \n{bob_inputs}')
    
    circuit_inputs = alice_inputs | bob_inputs

    # evaluate with inputs
    result = evaluate_circuit(config_json=data, circuit_inputs=circuit_inputs)

    print(f'result: {result}')

    if result == 0:
        print(f'Bob is richer')
    elif result == 1:
        print(f'Alice is richer')

