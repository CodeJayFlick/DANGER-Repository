Here is the equivalent Python code:

```Python
import struct

class XorMemoryScript:
    def run(self):
        # default to the current memory block
        memory = current_program.get_memory()
        block = memory.getBlock(current_address)
        set = AddressSetView(block.getStart(), block.getEnd())

        if current_selection != None and not current_selection.isEmpty():
            set = current_selection

        xor_values = input("XorValue: Values to xor with selected memory:")

        value_length = len(xor_values.encode())
        xor_index = 0

        for addr in set.getAddresses(True):
            monitor.setMessage(str(addr))
            xor_value = struct.unpack('B', xor_values.encode()[xor_index])[0]
            b = memory.getByte(addr)
            b ^= xor_value
            memory.setByte(addr, b)
            xor_index += 1
            if xor_index >= value_length:
                xor_index %= value_length

# usage example
script = XorMemoryScript()
script.run()
```

Please note that this Python code is not a direct translation of the original Ghidra script. It's an equivalent implementation in Python, but it may behave slightly differently due to differences between languages and their respective libraries.