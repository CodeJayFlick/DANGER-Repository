Here is the translation of the given Java code into Python:

```Python
class PdbRegisterNameToProgramRegisterMapper:
    def __init__(self, program):
        self.program = program
        self.pdb_register_name_to_register_map = {}

    def get_register(self, pdb_register_name):
        register = self.pdb_register_name_to_register_map.get(pdb_register_name)
        if register is not None:
            return register

        register_name = REGISTER_NAME_MAP.get(pdb_register_name)
        if register_name is None:
            register_name = pdb_register_name
        register = self.program.get_register(register_name)
        self.pdb_register_name_to_register_map[pdb_register_name] = register
        if register is None:
            print(f"Program register not found for {register_name}")
        return register


REGISTER_NAME_MAP = {"fbp": "RBP"}

# Example usage:
program = ...  # Initialize your program object here
mapper = PdbRegisterNameToProgramRegisterMapper(program)
register = mapper.get_register("fbp")
```

Note that Python does not have a direct equivalent to Java's `Map.of()` method, so the register name map is defined as a dictionary literal. Also, Python's print function is used instead of Msg.info() for logging messages.