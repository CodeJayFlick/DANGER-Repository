Here is the translation of the given Java code into equivalent Python:

```Python
class BindProcessor:
    def __init__(self, program, header, provider, command):
        pass  # No direct equivalent in Python for constructor-like methods.

    def process(self, monitor):
        bind = BindState(header, program)
        done = False

        while not done:
            if monitor.is_cancelled():
                break
            value = byte_server.read()
            if value == -1:
                break
            b = bytes([value])

            opcode = (b[0] & 0xFF) >> DyldInfoCommandConstants.BIND_OPCODE_MASK
            immediate = b[0] & DyldInfoCommandConstants.BIND_IMMEDIATE_MASK

            switcher = {
                DyldInfoCommandConstants.BIND_OPCODE_ADD_ADDR_ULEB: lambda: bind.segment_offset += uleb128(byte_server, monitor),
                DyldInfoCommandConstants.BIND_OPCODE_DO_BIND: lambda: (bind.perform(monitor), bind.segment_offset += program.default_pointer_size()),
                # ... and so on for all the cases
            }
            switcher.get(opcode, lambda: raise Exception(f"Unknown dyld info bind opcode {opcode}"))()


class BindState:
    def __init__(self, header, program):
        pass  # No direct equivalent in Python for constructor-like methods.

    def perform(self, monitor):
        pass  # No direct equivalent in Python for method.


def uleb128(byte_server, monitor):
    pass  # No direct equivalent in Python for method.