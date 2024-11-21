class GdbReadRegistersCommand:
    BYTE_ARRAY_KEY = {"v1_int8", "v2_int8", "v4_int8", "v8_int8", "v16_int8", "v32_int8", "v64_int8",
                       "u8"}

    def __init__(self, manager, thread, frame_id, regs):
        self.manager = manager
        self.thread = thread
        self.frame_id = frame_id
        self.regs = regs

    def encode(self, thread_part, frame_part):
        if not self.regs:
            return "-interpreter-exec console echo"
        b = StringBuilder()
        b.append("-data-list-register-values")
        b.append(thread_part)
        b.append(frame_part)
        b.append(" x")
        for r in self.regs:
            b.append(" ")
            b.append(str(r.get_number()))
        return str(b)

    def pack_elements(self, av, byte_count, bytes_per):
        assert bytes_per * len(av) == byte_count
        elems = [str(x).encode('utf-8') if isinstance(x, int) else x for x in av]
        packed = bytearray(byte_count)
        buf = memoryview(packed)
        i = 0
        step = -bytes_per if self.thread.get_inferior().get_endianness() == 'little' else bytes_per
        for elem in elems:
            buf[i:i+step] = elem.encode('utf-8') + b'\00'
            i += step
        return int.from_bytes(packed, byteorder='big')

    def parse_and_find_integer(self, val, byte_count):
        endianness = self.thread.get_inferior().get_endianness()
        if 'lbound' in val:
            return 0
        value = GdbCValueParser.parse_value(val)
        if isinstance(value, int):
            return value
        elif isinstance(value, dict) and 'values' in value:
            for v in value['values']:
                if isinstance(v, int):
                    return v
        elif isinstance(value, list):
            av = [str(x).encode('utf-8') if isinstance(x, int) else x for x in value]
            bytes_per = byte_count // len(av)
            return self.pack_elements(av, byte_count, bytes_per)

    def complete(self, pending):
        done = pending.check_completion(GdbCommandDoneEvent)
        if not self.regs:
            return {}
        regs_by_number = {r.get_number(): r for r in self.regs}
        value_list = [x.assume_register_value_list() for x in done]
        result = {}
        for fields in value_list:
            number = int(fields['number'])
            value = str(fields['value'])
            if number not in regs_by_number:
                Msg.error(self, f"GDB gave value for non-requested register: {number}")
                continue
            r = regs_by_number[number]
            try:
                result[r] = self.parse_and_find_integer(value, r.get_size())
            except (GdbParseError, AssertionError) as e:
                Msg.warn(self, f"Could not figure register value for [{number}] = {value}", e)
        return result
