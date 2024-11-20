class WdexConstants:
    MAGIC = "wdex"
    kVdexInvalidMagic = MAGIC

    @staticmethod
    def is_wdex(program):
        if program is not None:
            try:
                bytes_array = bytearray(MAGIC.encode())
                program.get_memory().get_bytes(program.get_min_address(), bytes_array)
                return MAGIC == bytes_array.decode()
            except Exception as e:
                pass  # ignore exceptions
        return False

# Example usage:
program = ...  # your Program object here
if WdexConstants.is_wdex(program):
    print("The program contains WDEX information.")
else:
    print("The program does not contain WDEX information.")
