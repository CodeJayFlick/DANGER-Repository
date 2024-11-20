Here is the translation of the given Java code into Python:

```Python
class SetLabelNamespaceCmd:
    def __init__(self, addr, name, old_namespace, new_namespace):
        self.addr = addr
        self.name = name
        self.old_namespace = old_namespace
        self.new_namespace = new_namespace

    def apply_to(self, obj):
        if not isinstance(obj, dict):  # Assuming DomainObject is a dictionary in Python
            return False
        
        symbol_table = obj.get('symbol_table')
        
        try:
            symbol = symbol_table[self.name]
        except KeyError:  # No symbol named 'name' found at address 'addr'
            self.error_msg = f"No symbol named {self.name} found at address {self.addr}"
            return False

        if not isinstance(symbol, dict):  # Assuming Symbol is a dictionary in Python
            self.error_msg = f"Symbol '{self.name}' already exists in namespace '{new_namespace}'"
            return True
        
        try:
            symbol['namespace'] = self.new_namespace
            return True
        except Exception as e:  # InvalidInputException or CircularDependencyException
            self.error_msg = str(e)
        
    def get_name(self):
        return "Set Namespace"

    def get_status_msg(self):
        return self.error_msg

# Example usage:
addr = '0x12345678'
name = 'my_label'
old_namespace = 'namespace1'
new_namespace = 'namespace2'

cmd = SetLabelNamespaceCmd(addr, name, old_namespace, new_namespace)
program = {'symbol_table': {}}
result = cmd.apply_to(program)

print(cmd.get_name())  # Output: "Set Namespace"
if result:
    print("Command applied successfully")
else:
    print(f"Error message: {cmd.get_status_msg()}")
```

Please note that the Python code is a translation of the given Java code and might not be exactly equivalent. The `DomainObject` in Java seems to have been replaced with a dictionary (`dict`) in Python, as there's no direct equivalent in Python for this class.