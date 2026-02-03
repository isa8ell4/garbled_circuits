import sys, json
from alice import Alice
from bob import Bob


if __name__ == "__main__":

    entity_type = None
    config_path = None

    args = sys.argv[1:]

    # read args from command line input
    for i, arg in enumerate(args):
        if arg == "alice":
            entity_type = "alice"
        elif arg == "bob":
            entity_type = "bob"
        elif arg == "-c":
            config_path = args[i + 1]
        elif arg == "-i":
            wealth = int(args[i+1])

    # open and read json
    config = None
    if config_path is not None:
        with open(config_path, "r") as f:
            config = json.load(f)

    if config == None:
        raise ValueError(f'config was not loaded properly')
    
    # create entity
    if entity_type == 'alice':
        entity = Alice(config, wealth)
    elif entity_type == 'bob':
        entity = Bob(config, wealth)
    else: 
        raise ValueError("Must specify alice or bob")

    entity.start()

    

    


    

    