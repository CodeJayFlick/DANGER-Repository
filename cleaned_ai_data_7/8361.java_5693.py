class AbstractOemDefinableStringMsType:
    def __init__(self, pdb, reader):
        self.ms_assigned_oem_identifier = reader.parse_unsigned_short_val()
        self.oem_assigned_type_identifier = reader.parse_unsigned_short_val()
        self.record_numbers = []
        count = reader.parse_var_sized_count()
        for i in range(count):
            record_number = RecordNumber.parse(pdb, reader)
            self.record_numbers.append(record_number)
        self.remaining_bytes = reader.parse_bytes_remaining()

    def emit(self, builder, bind):
        builder.append("OEM Definable String\n")
        builder.append(f"  MSFT-assigned OEM Identifier: {self.ms_assigned_oem_identifier}\n")
        builder.append(f"  OEM-assigned Identifier: {self.oem_assigned_type_identifier}\n")
        builder.append(f"  count: {len(self.record_numbers)}\n")
        for i, record_number in enumerate(self.record_numbers):
            builder.append(f"    recordNumber[{i}]: 0x{record_number.get_number():08x}\n")
        builder.append(f"  additional data length: {len(self.remaining_bytes)}\n")

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category):
        # This method is not implemented in the original Java code.
        pass

# Assuming you have a PdbByteReader class with these methods:
class PdbByteReader:
    def parse_unsigned_short_val(self):
        # Implement this method to read an unsigned short value
        pass

    def parse_var_sized_count(self, int_size):
        # Implement this method to read a variable-sized count
        pass

    def parse_bytes_remaining(self):
        # Implement this method to read the remaining bytes
        pass

# Assuming you have an AbstractPdb class:
class AbstractPdb:
    pass

# Assuming you have a StringBuilder and Bind classes in Python, similar to Java's.
