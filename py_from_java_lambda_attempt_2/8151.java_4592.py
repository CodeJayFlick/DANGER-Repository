Here is the translation of the given Java code into Python:

```Python
class DiscardedByLinkMsSymbol:
    PDB_ID = 0x113b
    
    class DiscardReason(enum.Enum):
        INVALID = "", -1
        UNKNOWN = "Unknown", 0
        NOT_SELECTED = "Not selected", 1
        NOT_REFERENCED = "Not referenced", 2
        
        BY_VALUE = {reason.value: reason for reason in enummembers()}
        
        def __str__(self):
            return self.label
        
        @classmethod
        def from_value(cls, val):
            return cls.BY_VALUE.get(val, DiscardReason.INVALID)
    
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        fields = reader.parse_unsigned_int_val()
        self.discarded_val = (fields & 0xff)
        self.discard = DiscardReason.from_value(self.discarded_val)
        self.file_id = reader.parse_unsigned_int_val()
        self.first_line_number = reader.parse_unsigned_int_val()
        data = reader.parse_bytes_remaining()
        
    def get_ordered_symbols(self, symbols_by_offset):
        offsets = list(symbols_by_offset.keys())
        symbols = []
        for offset in offsets:
            symbols.append(symbols_by_offset[offset])
        return symbols
    
    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: ")
        
        if self.discard == DiscardReason.UNKNOWN:
            builder.append(f"({hex(self.discarded_val)})")
        else:
            builder.append(str(self.discard))
            
        if self.file_id != 0xffffffff:
            builder.append(f", FileId: {format(self.file_id, '08X')} ")
            builder.append(f", Line: {self.first_line_number}\n")
        
        for symbol in self.symbol_list:
            builder.append(symbol)
            builder.append("\n")
    
    def get_symbol_type_name(self):
        return "DISCARDED"
```

Please note that Python does not have direct equivalent of Java's enum. We use the `enum` module from Python 3.4 onwards to create an enumeration in Python.