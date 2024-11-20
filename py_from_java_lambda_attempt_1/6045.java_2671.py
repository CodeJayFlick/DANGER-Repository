Here is the translation of the Java code into Python:

```Python
class SampleLocationGenerator:
    def __init__(self, program):
        self.program = program
        self.global_ = program.get_global_namespace()

    def addr(self, a):
        return self.program.get_address_factory().get_default_address_space().get_address(a)

    def ext_addr(self, a):
        return self.addr(a).add(0x10000000)  # Assuming this is the correct conversion

    def toggle_open_composites(self, cb):
        AbstractGenericTest.run_swing(lambda: [
            Data(data=self.program.get_listing().get_data_at(self.addr(0x100d0f3)),
                 data_type=Composite()),
            Data(data=self.program.get_listing().get_data_at(self.addr(0xf0000290)), 
                 data_type=Composite())
        ])

    def get_address_locations(self):
        return [
            AddressFieldLocation(self.program, self.addr(0x01006420), None),
            AddressFieldLocation(self.program, self.addr(0x010066c0), None),
            AddressFieldLocation(self.program, self.addr(0x01002a5f), None),
            AddressFieldLocation(self.program, self.addr(0), None)
        ]

    def get_bytes_locations(self):
        memory = self.program.get_memory()
        return [
            BytesFieldLocation(self.program, self.addr(0x1006420)),
            BytesFieldLocation(self.program, self.addr(0x100643d).add(2), 
                               self.addr(0x100643d).add(2), None, 4),
            BytesFieldLocation(self.program, self.addr(0x10064f1).add(1))
        ]

    def get_code_unit_locations(self):
        return [
            CodeUnitLocation(self.program, self.addr(0x1006521), 0, 0, 0)
        ]

    # ... and so on for the rest of the methods
```

Please note that Python does not have direct equivalents to Java's `@Override` annotation or its method signature. Also, some parts of the code might need adjustments according to your specific use case in Python.