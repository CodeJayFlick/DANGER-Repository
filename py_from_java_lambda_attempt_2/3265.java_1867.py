Here is the translation of the Java code into Python:

```Python
class SetRegisterCmd:
    def __init__(self, register, start, end, value):
        if start.address_space != end.address_space:
            raise ValueError("start and end address must be in the same address space")
        
        self.register = register
        self.start = start
        self.end = end
        self.value = value

    def apply_to(self, obj):
        program = Program(obj)
        context = program.get_program_context()

        try:
            context.set_value(self.register, self.start, self.end, self.value)
        except Exception as e:
            self.error_message = str(e)
            print(f"Error: {self.error_message}")
            return False
        return True

    def get_status_msg(self):
        return self.error_message if hasattr(self, 'error_message') else ''

    def get_name(self):
        return "Set Register Value"
```

Note that Python does not have direct equivalents for Java's `BigInteger` and `Address`, so I did not include those in the translation. Also, error handling is different between Java and Python - in this code, any exception raised during execution of the command will be caught and printed to the console.