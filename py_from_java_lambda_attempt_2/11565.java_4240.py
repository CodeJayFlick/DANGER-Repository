Here is the translation of the given Java code into Python:

```Python
class BreakTableCallBack:
    DEFAULT_NAME = "*"

    def __init__(self, language):
        self.language = language
        self.emulate = None
        self.address_callback = {}
        self.pcode_callback = {}
        self.default_pcode_callback = None

    def register_pcode_callback(self, name, func):
        if name == self.DEFAULT_NAME:
            self.default_pcode_callback = func
            return
        for i in range(len(self.language.user_defined_op_names)):
            if name == self.language.user_defined_op_names[i]:
                self.pcode_callback[long(i)] = func
                return
        raise LowlevelError("Bad userop name: " + name)

    def unregister_pcode_callback(self, name):
        if name == self.DEFAULT_NAME:
            self.default_pce_callback = None
            return
        for i in range(len(self.language.user_defined_op_names)):
            if name == self.language.user_defined_op_names[i]:
                del self.pcode_callback[long(i)]
                return
        raise LowlevelError("Bad userop name: " + name)

    def register_address_callback(self, addr, func):
        self.address_callback[addr] = func

    def unregister_address_callback(self, addr):
        if addr in self.address_callback:
            del self.address_callback[addr]

    def set_emulate(self, emu):
        self.emulate = emu
        for pair in list(self.address_callback.items()):
            pair[1].set_emulate(emu)
        if self.default_pce_callback is not None:
            self.default_pce_callback.set_emulate(emu)
        for pair in list(self.pcode_callback.items()):
            pair[1].set_emulate(emu)

    def do_pcode_op_break(self, curop):
        val = curop.get_input(0).get_offset()
        if long(val) not in self.pcode_callback:
            return False
        func = self.pcode_callback[val]
        return func.pce_callback(curop)

    def do_address_break(self, addr):
        if addr not in self.address_callback:
            return False
        func = self.address_callback[addr]
        return func.address_callback(addr)
```

Note that this is a direct translation of the Java code into Python. The original Java code seems to be part of an emulator system and uses various classes from other parts of the system, which are not provided here.