class ExpandBlockDownModel:
    def __init__(self, tool, program):
        pass

    def execute(self):
        message = ""
        length = self.end_addr - self.block.get_end()
        if length == 0:
            return True
        try:
            start_addr = self.end_addr - (length-1)
            return self.expand_block()
        except Exception as e:
            message = str(e)

    def set_length(self, length):
        self.message = ""
        self.length = length
        if self.is_valid_length():
            try:
                self.end_addr = self.block.get_start() + (length - 1)
            except AddressOverflowException as e:
                self.message = "Expanded block is too large"
        listener.state_changed(None)

    def set_end_address(self, addr):
        self.message = ""
        self.end_addr = addr
        if self.end_addr == None:
            self.message = "Invalid Address"
        elif self.block.get_end() >= self.end_addr:
            self.message = f"End must be greater than {self.block.get_end()}"
        else:
            self.length = self.end_addr - self.block.get_start() + 1
        listener.state_changed(None)

    def set_start_address(self, addr):
        pass

class Address:
    def __init__(self, value):
        self.value = value

    @staticmethod
    def add_no_wrap(a, b):
        return a + (b - len(str(b)))

    def subtract(self, other):
        return self.value - other.value

    def get_start(self):
        pass

class Program:
    def __init__(self, value):
        self.value = value

    def get_end(self):
        pass

    @staticmethod
    def add_no_wrap(a, b):
        return a + (b - len(str(b)))

# Example usage:

tool = "Ghidra"
program = "Program"

block = Program(program)
end_addr = Address(0x10000000)

model = ExpandBlockDownModel(tool, block)
print(model.execute())
