import struct

class Apple8900Util:
    MAGIC_BYTES = bytes([0x89, 0x00])

    @staticmethod
    def is_8900(program):
        try:
            min_address = program.getMinAddress()
            data = bytearray(4)
            program.getMemory().getBytes(min_address, data)
            return struct.pack('I', *data) == Apple8900Util.MAGIC_BYTES
        except Exception as e:
            pass  # ignore exceptions for now

# Example usage:
program = Program()  # assuming you have a `Program` class in Python
if Apple8900Util.is_8900(program):
    print("The program is an Apple 8900")
else:
    print("The program is not an Apple 8900")
