Here is the translation of the given Java code into Python:

```Python
class ExpandBlockModel:
    def __init__(self, tool, program):
        self.tool = tool
        self.program = program
        self.start_addr = None
        self.end_addr = None
        self.block_start = None
        self.length = 0
        self.block = None
        self.message = ""
        self.listener = None

    def domain_object_changed(self, ev):
        if not ev.contains_event(DomainObject.DO_OBJECT_RESTORED):
            return

        if self.block_start is None:
            return  # Not yet initialized

        updated_block = self.program.get_memory().get_block(self.block_start)
        self.initialize(updated_block)

    def initialize(self, new_block):
        self.block = new_block
        self.length = new_block.size()
        self.start_addr = new_block.start_address()
        self.end_addr = new_block.end_address()
        self.block_start = self.start_addr
        self.message = ""
        if self.listener is not None:
            self.listener.state_changed(None)

    def set_change_listener(self, listener):
        self.listener = listener

    @property
    def message_(self):
        return self.message

    @property
    def start_address_(self):
        return self.start_addr

    @property
    def end_address_(self):
        return self.end_addr

    @property
    def length_(self):
        return self.length

    def set_start_address(self, addr):
        pass  # Abstract method

    def set_end_address(self, addr):
        pass  # Abstract method

    def set_length(self, length):
        pass  # Abstract method

    def execute(self):
        raise NotImplementedError("Abstract method")

    def expand_block(self):
        cmd = ExpandBlockCmd(self.block)
        if not self.tool.execute(cmd, self.program):
            self.message = cmd.status_msg()
            self.tool.set_status_info(self.message)
            return False
        return True

    @property
    def is_valid_length_(self):
        block_size = self.block.size()
        if self.length <= block_size:
            self.message = f"Block size must be greater than {block_size}"
            return False
        elif self.length < 0 or self.length > int(2**31 - 1):
            self.message = "Expanded block is too large"
            return False
        return True

    def dispose(self):
        self.tool = None
        self.program.remove_listener(self)
        self.program = None


class ExpandBlockCmd:
    def __init__(self, expand_block):
        self.expand_block = expand_block
        self.msg = ""

    def apply_to(self, obj):
        program = Program(obj)
        memory = program.get_memory()
        try:
            new_block = memory.create_block(
                self.expand_block,
                f"{self.expand_block.name}.exp",
                self.start_address_,
                self.length_
            )
            block = memory.join(self.expand_block, new_block)
            if not block.name.endswith(".exp"):
                block.set_name(f"{block.name}.exp")
        except Exception as e:
            self.msg = str(e)

    @property
    def name_(self):
        return "Expand Block"

    @property
    def status_msg_(self):
        return self.msg


class DomainObjectChangedEvent:
    DO_OBJECT_RESTORED = 1

# Note: Python does not have direct equivalent of Java's abstract class.
```

This translation is based on the assumption that you want to keep the same structure and functionality as in the original Java code.