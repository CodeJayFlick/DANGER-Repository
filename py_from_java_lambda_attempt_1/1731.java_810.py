Here is the translation of the given Java code into equivalent Python:

```Python
class LldbModelTargetStackFrameRegisterImpl:
    def __init__(self, bank: 'LldbModelTargetStackFrameRegisterBankImpl', register):
        super().__init__(bank.model, bank, self.key_register(register), register, "Register")
        self.value = str(self.get_value())

        attributes = {
            ghidra.dbg.target.schema.CONTAINER_ATTRIBUTE_NAME: bank.container,
            ghidra.dbg.target.schema.LENGTH_ATTRIBUTE_NAME: self.bit_length(),
            ghidra.dbg.target.schema.DISPLAY_ATTRIBUTE_NAME: self.description(0),
            ghidra.dbg.target.schema.VALUE_ATTRIBUTE_NAME: str(self.value) if self.value else "0",
            ghidra.dbg.target.schema.MODIFIED_ATTRIBUTE_NAME: False
        }
        self.change_attributes([], attributes, "Initialized")

    @staticmethod
    def index_register(register):
        return register.name

    @staticmethod
    def key_register(register):
        return PathUtils.make_key(LldbModelTargetStackFrameRegisterImpl.index_register(register))

    @property
    def value(self):
        return str(self.get_value())

    def get_description(self, level: int) -> str:
        stream = SBStream()
        val = self.model_object
        val.GetDescription(stream)
        return stream.data

    def bit_length(self) -> int:
        return (self.register.ByteSize() * 8)

    @property
    def register(self):
        return self.model_object

    def get_value(self) -> str:
        if not self.value:
            return None
        if not self.value.startswith("0x"):
            return self.value
        return self.value[2]

    def get_bytes(self) -> bytes:
        old_value = self.value
        self.value = str(self.get_value())
        if not self.value:
            return bytearray()
        val = BigInteger(self.value, 16)
        bytes_ = ConversionUtils.bigIntegerToBytes((self.register.ByteSize()), val)
        attributes = {
            ghidra.dbg.target.schema.VALUE_ATTRIBUTE_NAME: self.value
        }
        self.change_attributes([], attributes, "Refreshed")
        if val.long_value() != 0:
            newval = self.description(0)
            attributes[ghidra.dbg.target.schema.DISPLAY_ATTRIBUTE_NAME] = newval
            self.set_modified(not old_value == self.value)
        return bytes_

    def get_display(self) -> str:
        return f"{self.name} : {str(self.get_value())}" if not self.value else f"{self.name}"

class LldbModelTargetStackFrameRegisterBankImpl:

# You would need to implement the methods in this class
```

Note that I've used Python's built-in `bytearray` type for representing byte arrays, and the `@property` decorator is used to create getter/setter properties. Also, some Java-specific classes like `BigInteger`, `SBStream`, etc., are not available in Python by default, so you would need to use equivalent libraries or implement them yourself if needed.