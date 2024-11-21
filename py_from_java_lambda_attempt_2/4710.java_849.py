Here is the translation of the given Java code into equivalent Python:

```Python
class AndroidElfRelocationGroup:
    def __init__(self):
        self.base_relloc_offset = None
    
    @staticmethod
    def get_relocation_grouped_by_info_flag():
        return 1
    
    @staticmethod
    def get_relocation_grouped_by_offset_delta_flag():
        return 2
    
    @staticmethod
    def get_relocation_grouped_by_addend_flag():
        return 4
    
    @staticmethod
    def get_relocation_group_has_addend_flag():
        return 8

    def clone(self):
        raise UnsupportedOperationException("may not be cloned")

    def get_description(self):
        return "Android Packed Relocation Entry Group for ELF"

    def get_value(self, buf, settings, length):
        return None
    
    def get_representation(self, buf, settings, length):
        return ""

    @staticmethod
    def parse_leb128_info(reader):
        sleb128 = LEB128Info()
        sleb128.parse(reader)
        return sleb128

    def get_components(self, buf):
        try:
            provider = MemBufferByteProvider(buf)
            reader = BinaryReader(provider, False)

            components_list = []

            sleb128 = self.parse_leb128_info(reader)
            group_size = sleb128.value
            components_list.append(sleb128.get_component("group_ size", None))

            sleb128 = self.parse_leb128_info(reader)
            group_flags = sleb128.value

            grouped_by_info = (group_flags & AndroidElfRelocationGroup.get_relocation_grouped_by_info_flag()) != 0
            grouped_by_delta = (group_flags & AndroidElfRelocationGroup.get_relocation_grouped_by_offset_delta_flag()) != 0
            grouped_by_addend = (group_flags & AndroidElfRelocationGroup.get_relocation_grouped_by_addend_flag()) != 0
            group_has_addend = (group_flags & AndroidElfRelocationGroup.get_relocation_group_has_addend_flag()) != 0

            if grouped_by_delta:
                sleb128 = self.parse_leb128_info(reader)
                group_offset_delta = sleb128.value

                min_offset = self.base_relloc_offset + group_offset_delta
                range_str = f"First relocation offset: {min_offset:x}"
                components_list.append(sleb128.get_component("group_ offsetDelta", range_str))

            if grouped_by_info:
                sleb128 = self.parse_leb128_info(reader)
                components_list.append(sleb128.get_component("group_ info", None))

            if (grouped_by_addend and group_has_addend):
                sleb128 = self.parse_leb128_info(reader)
                components_list.append(sleb128.get_component("group_ addend", None))

            reloc_offset = self.base_relloc_offset

            if grouped_by_delta and grouped_by_info and not(group_has_addend or grouped_by_addend):
                # no individual relocation entry data
                reloc_offset += (group_size - 1) * group_offset_delta
            else:
                for i in range(group_size):
                    if grouped_by_delta:
                        reloc_offset += group_offset_delta
                    elif grouped_by_info and not(grouped_by_addend or group_has_addend):
                        sleb128 = self.parse_leb128_info(reader)
                        base_offset = reloc_offset
                        reloc_offset += sleb128.value

                        dtc = ReadOnlyDataTypeComponent(
                            AndroidElfRelocationOffset(self, base_offset, reloc_offset),
                            self,
                            sleb128.byte_length,
                            len(components_list) + 1,
                            "reloc_ offset_" + str(i),
                            None)
                        components_list.append(dtc)

                    if not(grouped_by_info):
                        sleb128 = self.parse_leb128_info(reader)
                        components_list.append(sleb128.get_component("reloc_ info_" + str(i), None, reloc_offset))

                    if group_has_addend and not grouped_by_addend:
                        sleb128 = self.parse_leb128_info(reader)
                        components_list.append(sleb128.get_component("reloc_ addend_" + str(i), None, reloc_offset))

            return [DataTypeComponent(x) for x in components_list]
        except IOException as e:
            return []

    def get_last_relocation_offset(self, buf):
        comps = self.get_components(buf)
        if not(comps or len(comps) < 3):
            return -1

        # group_ size component
        s = Scalar()
        for dtc in comps[:2]:
            s.parse(dtc.get_data_type().get_value(buf, None, dtc.length))
        group_size = int(s.value)

        last_dtc = comps[-1]

        if "group_ offsetDelta".startswith(last_dtc.field_name):
            cbuf = WrappedMemBuffer(buf, last_dtc.offset)
            s.parse(cbuf.get_data_type().get_value(cbuf, None, dtc.length))
            group_offset_delta = int(s.value)
            return self.base_relloc_offset + ((group_size - 1) * group_offset_delta)

        if last_dtc.field_name.startswith("group_"):
            return -1

        dt = last_dtc.data_type
        if isinstance(dt, AndroidElfRelocationOffset):
            d = AndroidElfRelocationOffset(self)
            d.parse(dt.get_value(buf, None, dt.length))
            return int(d.relocation_offset)

        elif isinstance(dt, AndroidElfRelocationData):
            d = AndroidElfRelocationData(self)
            d.parse(dt.get_value(buf, None, dt.length))
            return int(d.relocation_offset)

        return -1
```

Please note that Python does not support static methods or final modifiers like Java. Also, Python's `long` type is equivalent to Java's `int`, and it can handle large integers without overflow.