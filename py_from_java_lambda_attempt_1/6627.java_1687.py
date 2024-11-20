Here is the translation of the given Java code into equivalent Python:

```Python
class FuncRecord:
    def __init__(self):
        self.func = None
        self.func_name = ""
        self.hash_value = 0x12345678
        self.children = []
        self.calls = []

    def __init__(self, func):
        self.func = func
        # Symbol[] symbols = func.getProgram().getSymbolTable().getSymbols(func.getEntryPoint());
        self.func_name = str(func)
        self.hash_value = 0x12345678
        self.children = []
        self.calls = []

    def calculate_signature(self, func):
        listing = func.get_program().get_listing()
        seen_ranges = set()
        body = func.get_body()
        init_range = body.get_range_containing(func.get_entry_point())
        queue = [init_range]
        seen_ranges.add(init_range)
        function_manager = func.get_program().get_function_manager()

        while queue:
            cur_range = queue.pop(0)
            cur_view = set(cur_range)
            code_unit_iterator = listing.get_code_units(cur_view, True)

            while code_unit_iterator.has_next():
                unit = code_unit_iterator.next()
                if not isinstance(unit, Instruction):
                    continue

                instruction = unit
                local_calls = instruction.get_flows()

                if local_calls and len(local_calls) > 1:
                    local_calls.sort()
                if local_calls:
                    for call in local_calls:
                        possible_call = function_manager.get_function_containing(call)
                        if possible_call and possible_call.get_entry_point().equals(call):
                            self.calls.append(call)

            try:
                to_hash = instruction.get_bytes()
                for i, op_num in enumerate(instruction.get_operand_count()):
                    op_obs = instruction.get_op_objects(op_num)
                    for ob in op_obs:
                        if not isinstance(ob, Register) and not isinstance(ob, str):
                            mask_bytes = instruction.get_prototype().get_operand_value_mask(
                                op_num).get_bytes()
                            for j, byte in enumerate(mask_bytes):
                                to_hash[j] &= 0xff ^ byte

                total_to_hash = bytearray(to_hash + 8)
                for i in range(8):
                    total_to_hash[i] = (self.hash_value >> (i * 8)) % 256
                for index, byte in enumerate(to_hash):
                    total_to_hash[8 + index] = byte

                digest = FNV1a64MessageDigest()
                digest.reset()
                digest.update(total_to_hash, TaskMonitorAdapter.DUMMY_MONITOR)

                self.hash_value = digest.digest_long()

            except MemoryAccessException as e:
                print_stacktrace(e)

        address_flows = instruction.get_flows()
        if len(address_flows) > 1:
            address_flows.sort()
        for flow in address_flows:
            flow_range = body.get_range_containing(flow)
            if flow_range and not seen_ranges.contains(flow_range):
                queue.append(flow_range)
                seen_ranges.add(flow_range)

    def __str__(self):
        return f"{self.func_name},{self.hash_value}"

    def compare_to(self, o):
        first = self.hash_value - o.hash_value
        if first != 0:
            return first

        return self.func_name.lower().casefold() - o.func_name.lower().casefold()

    @staticmethod
    def restore_xml(parser):
        edges = []

        while parser.peek().is_start():
            el = parser.start("child")
            func_name = el.get_attribute("funcName")
            hash_val_str = el.get_attribute("hashVal")
            edges.append((func_name, long(hash_val_str)))

        return edges

    def save_xml(self, fwrite):
        buf = StringBuilder()
        buf.append("<funcRec")
        buf.append(f" funcName=\"{self.func_name}\"")
        buf.append(f" hashVal={self.hash_value}")
        buf.append(">\n")

        fwrite.write(buf.toString())

        for kid in self.children:
            buf = StringBuilder()
            buf.append("    <child name=\"")
            SpecXmlUtils.xml_escape(buf, kid.func_name)
            buf.append("\"/>\n")
        # NB: It is unnecessary to store parents and children, since when we create the graph from the file, we can create both sides simultaneously.

        buf.append("</funcRec>\n")
        fwrite.write(buf.toString())

    def __eq__(self, o):
        return self.hash_value == o.hash_value

    def __lt__(self, o):
        if self.hash_value < o.hash_value:
            return True
        elif self.hash_value > o.hash_value:
            return False
        else:
            return self.func_name.lower().casefold() < o.func_name.lower().casefold()
```

Please note that Python does not have direct equivalent of Java's `MessageDigest` and `FNV1a64MessageDigest`. You may need to use a library like `hashlib` or implement your own hash function.