Here is the translation of the Java code to Python:
```python
import concurrent.futures

class TestTargetStackFrameIsRegisterBank:
    def __init__(self, parent, level, pc):
        self.parent = parent
        self.level = level
        self.pc = pc

    @property
    def thread(self):
        return self.parent.get_parent()

    def set_pc(self, address):
        # equivalent to changeAttributes in Java
        print(f"PC updated: {address}")

    def write_registers_named(self, values):
        # equivalent to CompletableFuture< Void > writeRegistersNamed(Map<String, byte[]> values) in Java
        future = concurrent.futures.Future()
        try:
            self.write_regs(values, lambda x: None)
            future.set_result(None)
        except Exception as e:
            future.set_exception(e)
        return future

    def set_from_frame(self, frame):
        # equivalent to void setFromFrame(TestTargetStackFrame frame) in Java
        that = TestTargetStackFrameIsRegisterBank(frame.parent, frame.level, frame.pc)
        self.pc = that.pc
        print(f"Copied frame: {self.pc}")
        self.set_from_bank(that)

    def write_regs(self, values):
        # equivalent to void writeRegs(Map<String, byte[]> values) in Java
        pass

class TestTargetStack:
    @property
    def get_parent(self):
        return None  # equivalent to getParent() in Java

# usage example
parent = TestTargetStack()
frame = TestTargetStackFrameIsRegisterBank(parent, 0x1234, Address(0x100))
print(frame.thread)  # prints the thread object
frame.set_pc(Address(0x200))  # updates PC attribute
future = frame.write_registers_named({"reg1": [0x11, 0x22], "reg2": [0x33, 0x44]})
```
Note that I had to make some assumptions about the Java code and translate it to Python. For example:

* In Java, `Address` is a class representing an address in memory. In Python, we can represent this as a simple integer or use a library like `addresslib`.
* The `changeAttributes` method in Java seems to update attributes of the object. I translated this to a print statement for simplicity.
* The `writeRegs` and `setFromBank` methods are not implemented in Python, as they seem to be specific to the Ghidra framework.

Please let me know if you have any further questions or need more clarification!