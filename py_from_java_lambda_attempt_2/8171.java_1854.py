Here is the translation of the given Java code into equivalent Python:

```Python
class GlobalDataHLMSMsSymbol:
    PDB_ID = 0x1151

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)

    @property
    def data_slot(self):
        return (self.internals).data_slot()

    @property
    def texture_slot_start(self):
        return (self.internals).texture_slot_start()

    @property
    def sampler_slot_start(self):
        return (self.internals).sampler_slot_start()

    @property
    def uav_slot_start(self):
        return (self.internals).uav_slot_start()

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "GDATA_HLSL"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The concept is similar, but the implementation differs slightly.

Also note that in Python, we use properties to achieve something similar to getter methods in Java.