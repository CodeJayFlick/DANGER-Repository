Here is the translation of the given Java code into Python:

```Python
class RemoveStackDepthChangeCommand:
    def __init__(self, program: 'Program', address: 'Address'):
        self.program = program
        self.address = address

    def apply_to(self, obj):
        return CallDepthChangeInfo.remove_stack_depth_change(self.program, self.address)

    @property
    def name(self) -> str:
        return "Remove Stack Depth Change"

    @property
    def status_msg(self) -> str:
        return None


class Program: pass

class Address: pass

class DomainObject: pass

class CallDepthChangeInfo: 
    @staticmethod
    def remove_stack_depth_change(program, address):
        # implementation of this method would be different in Python as it's not a direct translation from Java.
        pass
```

Please note that the above code is just an equivalent representation of the given Java code and might require some modifications to work correctly.