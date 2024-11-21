Here is the translation of the given Java code into equivalent Python:

```Python
import io

class DebugInfoStateMachineReader:
    MAX_SIZE = 65536  # 64k in decimal

    @staticmethod
    def compute_length(reader):
        start = reader.tell()

        while True:
            opcode = reader.read(1)

            if opcode == b'\x00':  # DBG_END_SEQUENCE
                return int(reader.tell() - start)
            elif opcode == DebugStateMachineOpCodes.DBG_ADVANCE_PC:  # DBG_ADVANCE_PC
                LEB128.read_as_uint32(reader)
            elif opcode == DebugStateMachineOpCodes.DBG_ADVANCE_LINE:  # DBG_ADVANCE_LINE
                LEB128.read_as_uint32(reader)
            elif opcode == DebugStateMachineOpCodes.DBG_START_LOCAL:  # DBG_START_LOCAL
                register = LEB128.read_as_uint32(reader)

                name = LEB128.read_as_uint32(reader)  # TODO uleb128p1
                type = LEB128.read_as_uint32(reader)
            elif opcode == DebugStateMachineOpCodes.DBG_START_LOCAL_EXTENDED:  # DBG_START_LOCAL_EXTENDED
                register = LEB128.read_as_uint32(reader)

                name = LEB128.read_as_uint32(reader)  # TODO uleb128p1
                type = LEB128.read_as_uint32(reader)
                signature = LEB128.read_as_uint32(reader)  # TODO uleb128p1
            elif opcode == DebugStateMachineOpCodes.DBG_END_LOCAL:  # DBG_END_LOCAL
                register = LEB128.read_as_uint32(reader)
            elif opcode == DebugStateMachineOpCodes.DBG_RESTART_LOCAL:  # DBG_RESTART_LOCAL
                register = LEB128.read_as_uint32(reader)
            elif opcode == DebugStateMachineOpCodes.DBG_SET_PROLOGUE_END:  # DBG_SET_PROLOGUE_END
                pass
            elif opcode == DebugStateMachineOpCodes.DBG_SET_EPILOGUE_BEGIN:  # DBG_SET_EPILOGUE_BEGIN
                pass
            elif opcode == DebugStateMachineOpCodes.DBG_SET_FILE:  # DBG_SET_FILE
                name = LEB128.read_as_uint32(reader)  # TODO uleb128p1
            else:
                break

        return 0


class LEB128:
    @staticmethod
    def read_as_uint32(reader):
        pass  # implementation of reading a uint32 from the reader


# This is just an example, you need to implement this class and its methods
DebugStateMachineOpCodes = {
    'DBG_END_SEQUENCE': b'\x00',
    'DBG_ADVANCE_PC': b'\x01',  # DBG_ADVANCE_PC
    'DBG_ADVANCE_LINE': b'\x02',  # DBG_ADVANCE_LINE
    'DBG_START_LOCAL': b'\x03',  # DBG_START_LOCAL
    'DBG_START_LOCAL_EXTENDED': b'\x04',  # DBG_START_LOCAL_EXTENDED
    'DBG_END_LOCAL': b'\x05',  # DBG_END_LOCAL
    'DBG_RESTART_LOCAL': b'\x06',  # DBG_RESTART_LOCAL
    'DBG_SET_PROLOGUE_END': b'\x07',  # DBG_SET_PROLOGUE_END
    'DBG_SET_EPILOGUE_BEGIN': b'\x08',  # DBG_SET_EPILOGUE_BEGIN
    'DBG_SET_FILE': b'\x09'  # DBG_SET_FILE
}
```

Please note that this is a direct translation of the given Java code into Python. It does not necessarily mean it will work correctly or efficiently, as you would need to implement the `LEB128` class and its methods for reading uint32 values from the reader in your specific use case.