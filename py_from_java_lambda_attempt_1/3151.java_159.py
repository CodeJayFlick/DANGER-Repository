Here is the translation of the given Java code into equivalent Python:

```Python
class CreateDataCmd:
    def __init__(self, addr, force=False, stack_pointers=False, data_type=None):
        self.addr = addr
        self.data_type = data_type
        self.stack_pointers = stack_pointers
        if not data_type:
            raise ValueError("data type is required")
        if isinstance(force, bool) and (stack_pointers or not force):
            raise ValueError("force must be True when using pointer conversion")

    def apply_to(self, program):
        try:
            DataUtilities.create_data(program, self.addr, self.data_type, -1, self.stack_pointers)
            return True
        except Exception as e:
            self.msg = str(e)
            return False

    @property
    def status_msg(self):
        return self.msg

    @property
    def name(self):
        if not hasattr(self, 'cmd_name'):
            self.cmd_name = f"Create {self.data_type.get_display_name()}"
        return self.cmd_name


class DataUtilities:
    @staticmethod
    def create_data(program, addr, data_type, length=-1, stack_pointers=False):
        # implement the logic here

# usage example:

addr = Address(0x100)  # replace with your desired address
data_type = DataType("my_data_type")  # replace with your desired data type
cmd = CreateDataCmd(addr, force=True, stack_pointers=True, data_type=data_type)
program = Program()  # replace with your program object

if cmd.apply_to(program):
    print(f"Created {addr} as {data_type.get_display_name()} successfully")
else:
    print(cmd.status_msg)

print(cmd.name)  # prints "Create my_data_type"
```

Please note that this is a direct translation of the given Java code into Python, and it may not work perfectly without some modifications. The `DataUtilities` class in particular needs to be implemented according to your specific requirements.