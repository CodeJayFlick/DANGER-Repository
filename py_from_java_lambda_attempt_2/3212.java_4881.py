Here is the translation of the given Java code into Python:

```Python
class AddLabelCmd:
    def __init__(self, addr=None, name="", namespace=None, source=""):
        self.addr = addr
        self.name = name
        self.namespace = namespace
        self.source = source
        self.use_local_namespace = False

    @property
    def use_local_namespace(self):
        return self._use_local_namespace

    @use_local_namespace.setter
    def use_local_namespace(self, value):
        self._use_local_namespace = value

    def apply_to(self, obj):
        if isinstance(obj, Program):
            symbol_table = obj.get_symbol_table()
            if not self.namespace and self.use_local_namespace:
                self.namespace = symbol_table.get_namespace(self.addr)
            try:
                return symbol_table.create_label(self.addr, self.name, self.namespace, self.source)
            except Exception as e:
                if not self.name or len(self.name) == 0:
                    self.error_msg = "You must enter a valid label name"
                else:
                    self.error_msg = f"Invalid name: {e}"
        return False

    @property
    def error_msg(self):
        return self._error_msg

    @error_msg.setter
    def error_msg(self, value):
        self._error_msg = value

    def get_status_msg(self):
        return self.error_msg

    def __str__(self):
        return "Add Label"

class Program:
    def __init__(self):
        pass

    def get_symbol_table(self):
        # This method should be implemented in the actual program class
        raise NotImplementedError("Method not implemented")

if __name__ == "__main__":
    add_label_cmd = AddLabelCmd(addr=0x100, name="My Label", namespace=None)
    obj = Program()  # Replace with your actual object
    result = add_label_cmd.apply_to(obj)

```

Note: This Python code is a direct translation of the given Java code. However, it does not include all the necessary classes and methods as they are specific to the Ghidra framework which was used in the original Java code.