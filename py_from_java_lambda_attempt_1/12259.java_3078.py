Here is the translation of the Java code into Python:

```Python
class CompositeInternal:
    ALIGN_NAME = "aligned"
    PACKING_NAME = "pack"
    DISABLED_PACKING_NAME = "disabled"
    DEFAULT_packing_name = ""

    DEFAULT_PACKING = 0
    NO_PACKING = -1

    def __init__(self):
        pass

    @property
    def stored_packing_value(self):
        return self._stored_packing_value

    @stored_packing_value.setter
    def stored_packing_value(self, value):
        if isinstance(value, int) and (value == DEFAULT_PACKING or value == NO_PACKING):
            self._stored_packing_value = value
        else:
            raise ValueError("Invalid packing value")

    @property
    def stored_minimum_alignment(self):
        return self._stored_minimum_alignment

    @stored_minimum_alignment.setter
    def stored_minimum_alignment(self, value):
        if isinstance(value, int) and (value == DEFAULT_ALIGNMENT or value == MACHINE_ALIGNMENT):
            self._stored_minimum_alignment = value
        else:
            raise ValueError("Invalid minimum alignment")

class ComponentComparator:
    INSTANCE = None

    @staticmethod
    def compare(dtc1, dtc2):
        return dtc1.ordinal - dtc2.ordinal


class OffsetComparator:
    INSTANCE = None

    @staticmethod
    def compare(o1, o2):
        if isinstance(o1, int) and isinstance(o2, int):
            return o2 - o1
        elif isinstance(o1, DataTypeComponent) and isinstance(o2, int):
            offset = o2
            if offset < o1.offset:
                return 1
            elif offset > o1.end_offset():
                return -1
            else:
                return 0


class OrdinalComparator:
    INSTANCE = None

    @staticmethod
    def compare(o1, o2):
        if isinstance(o1, int) and isinstance(o2, int):
            return o2 - o1
        elif isinstance(o1, DataTypeComponent) and isinstance(o2, int):
            ordinal = o2
            return o1.ordinal - ordinal


def get_alignment_and_packing_string(composite):
    buf = StringBuilder(get_min_alignment_string(composite))
    if buf.length() != 0:
        buf.append(" ")
    buf.append(get_packing_string(composite))
    return str(buf)


def get_min_alignment_string(composite):
    if composite.is_default_aligned():
        return ""
    else:
        buf = StringBuilder(CompositeInternal.ALIGN_NAME)
        buf.append("(")
        if composite.is_machine_aligned():
            buf.append("machine:")
            buf.append(str(composite.data_organization.machine_alignment))
        else:
            buf.append(str(composite.explicit_minimum_alignment))
        buf.append(")")
        return str(buf)


def get_packing_string(composite):
    buf = StringBuilder(CompositeInternal.PACKING_NAME)
    buf.append("(")
    if composite.is_packing_enabled():
        if composite.has_explicit_packing_value():
            buf.append(str(composite.explicit_packing_value))
        else:
            buf.append(CompositeInternal.DEFAULT_PACKING_NAME)
    else:
        buf.append(CompositeInternal.DISABLED_PACKING_NAME)  # NO_ PACKING
    buf.append(")")
    return str(buf)


def dump_components(composite, buffer, pad):
    components = composite.defined_components
    for dtc in components:
        data_type = dtc.data_type
        if isinstance(data_type, BitFieldDataType):
            bf_dt = data_type
            buffer.append(pad + " (")
            buffer.append(str(bf_dt.bit_offset))
            buffer.append(")")
        else:
            buffer.append(pad + str(dtc.offset) + " ")
            buffer.append(data_type.name)
        buffer.append(pad + str(dtc.length) + " ")
        buffer.append(dtc.field_name)
        comment = dtc.comment
        if comment is None:
            comment = ""
        buffer.append(pad + "\"" + comment + "\"")
        buffer.append("\n")


def type_name(composite):
    if isinstance(composite, Structure):
        return "Structure"
    elif isinstance(composite, Union):
        return "Union"


class DataTypeComponent:
    def __init__(self, ordinal, offset, length, field_name, data_type, comment=None):
        self.ordinal = ordinal
        self.offset = offset
        self.length = length
        self.field_name = field_name
        self.data_type = data_type
        self.comment = comment


class BitFieldDataType:
    def __init__(self, bit_offset):
        self.bit_offset = bit_offset


def main():
    # Example usage of the code

    composite1 = CompositeInternal()
    dtc1 = DataTypeComponent(0, 0, 4, "field_name", BitFieldDataType(8))
    dtc2 = DataTypeComponent(1, 4, 4, "another_field_name", BitFieldDataType(16))

    components = [dtc1, dtc2]
    composite1.defined_components = components

    buffer = StringBuilder()
    dump_components(composite1, buffer, "")
    print(buffer.toString())


if __name__ == "__main__":
    main()

```

Please note that this is a direct translation of the Java code into Python and might not be perfect or idiomatic Python.