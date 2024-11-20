Here is the translation of the Java code into Python:

```Python
class DataGatheringParams:
    def __init__(self):
        self.num_pre_bytes = None
        self.num_first_bytes = None
        self.num_return_bytes = None
        self.num_pre_instructions = None
        self.num_first_instructions = None
        self.num_return_instructions = None
        self.context_registers = []

    @property
    def num_pre_bytes(self):
        return self._num_pre_bytes

    @num_pre_bytes.setter
    def num_pre_bytes(self, value):
        self._num_pre_bytes = value

    @property
    def num_first_bytes(self):
        return self._num_first_bytes

    @num_first_bytes.setter
    def num_first_bytes(self, value):
        self._num_first_bytes = value

    @property
    def num_return_bytes(self):
        return self._num_return_bytes

    @num_return_bytes.setter
    def num_return_bytes(self, value):
        self._num_return_bytes = value

    @property
    def num_pre_instructions(self):
        return self._num_pre_instructions

    @num_pre_instructions.setter
    def num_pre_instructions(self, value):
        self._num_pre_instructions = value

    @property
    def num_first_instructions(self):
        return self._num_first_instructions

    @num_first_instructions.setter
    def num_first_instructions(self, value):
        self._num_first_instructions = value

    @property
    def num_return_instructions(self):
        return self._num_return_instructions

    @num_return_instructions.setter
    def num_return_instructions(self, value):
        self._num_return_instructions = value

    @property
    def context_registers(self):
        return self._context_registers

    @context_registers.setter
    def context_registers(self, value):
        if isinstance(value, list) and all(isinstance(x, str) for x in value):
            self._context_registers = value
        else:
            raise ValueError("Context registers must be a list of strings")

    @staticmethod
    def get_context_register_list(context_regs_csv):
        if context_regs_csv is None or not context_regs_csv.strip():
            return []

        components = [x.strip() for x in context_regs_csv.split(",") if x]
        return [component for component in components if component]

# Example usage:
params = DataGatheringParams()
print(params.num_pre_bytes)  # prints: None
```

Note that Python does not have direct equivalent of Java's `List` interface, so I used a list comprehension to filter out empty strings from the CSV string. Also, Python has no concept of getters and setters like in Java, but we can achieve similar functionality using properties (which are essentially getter-setter pairs).