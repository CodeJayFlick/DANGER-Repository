Here is the translation of the given Java code into Python:

```Python
class DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol:
    PDB_ID = 0x1158
    
    def __init__(self, pdb, reader):
        self.map_list = []
        
        while reader.has_more():
            entry = DeferredProcedureCallPointerTagToSymbolRecordMapEntry(reader)
            self.map_list.append(entry)

class DeferredProcedureCallPointerTagToSymbolRecordMapEntry:
    pass

def get_pdb_id(self):
    return self.PDB_ID

def emit(self, builder):
    builder.append(f"{self.get_symbol_type_name()}: {len(self.map_list)} entries")
    
    for entry in self.map_list:
        builder.append(f", {entry}")
        
    builder.append("\n")

def get_symbol_type_name(self):
    return "DPC_SYM_TAG_MAP"
```

Please note that this is a direct translation of the Java code into Python, and it might not be perfect. The `DeferredProcedureCallPointerTagToSymbolRecordMapEntry` class in the original Java code seems to have been omitted from the translation as there was no equivalent information provided for its implementation.