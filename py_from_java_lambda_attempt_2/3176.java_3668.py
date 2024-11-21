Here is the translation of the given Java code into Python:

```Python
class AddMemoryVarCmd:
    def __init__(self, mem_addr, first_use_addr, name, source):
        self.mem_addr = mem_addr
        self.first_use_addr = first_use_addr
        self.name = name
        self.source = source

    def apply_to(self, program):
        try:
            function = program.get_listing().get_function_containing(first_use_addr)
            if function is None:
                return False, "Address not contained within function: {}".format(first_use_addr)

            first_use_offset = int(first_use_addr) - int(function.get_entry_point())
            variable = LocalVariableImpl(name, first_use_offset, dt, mem_addr, program)
            function.add_local_variable(variable, source)
        except DuplicateNameException as e:
            return False, "Variable named {} already exists".format(name)
        except InvalidInputException as e:
            return False, "Variable named {}: {}".format(name, str(e))
        else:
            return True, ""

    def get_name(self):
        return "Create Memory Variable"

class LocalVariableImpl:
    def __init__(self, name, offset, dt, mem_addr, program):
        self.name = name
        self.offset = offset
        self.dt = dt
        self.mem_addr = mem_addr
        self.program = program

# Usage example:

mem_addr = 0x10000000
first_use_addr = 0x10100000
name = "my_var"
source = "some_source"

cmd = AddMemoryVarCmd(mem_addr, first_use_addr, name, source)
program = ... # assume you have a Program object

success, status_msg = cmd.apply_to(program)

if success:
    print("Command executed successfully")
else:
    print(status_msg)
```

Please note that Python does not support direct translation of Java code into Python. This is because both languages are fundamentally different and have their own unique features, syntax, and idioms.