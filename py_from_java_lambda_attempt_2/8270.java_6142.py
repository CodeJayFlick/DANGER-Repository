Here is the translation of the given Java code into Python:

```Python
class ProcedureFlags:
    def __init__(self):
        self.flag_byte = None
        self.frame_pointer_present = False
        self.interrupt_return = False
        self.far_return = False
        self.does_not_return = False
        self.label_not_reached = False
        self.custom_calling_convention = False
        self.marked_as_no_inline = False
        self.has_debug_information_for_optimized_code = False

    def process_flags(self, val):
        self.frame_pointer_present = (val & 0x0001) == 0x0001
        val >>= 1
        self.interrupt_return = (val & 0x0001) == 0x0001
        val >>= 1
        self.far_return = (val & 0x0001) == 0x0001
        val >>= 1
        self.does_not_return = (val & 0x0001) == 0x0001
        val >>= 1
        self.label_not_reached = (val & 0x0001) == 0x0001
        val >>= 1
        self.custom_calling_convention = (val & 0x0001) == 0x0001
        val >>= 1
        self.marked_as_no_inline = (val & 0x0001) == 0x0001
        val >>= 1
        self.has_debug_information_for_optimized_code = (val & 0x0001) == 0x0001

    def emit(self):
        print("Flags: Frame Ptr Present:", self.frame_pointer_present)
        print("Interrupt Return:", self.interrupt_return)
        print("FAR Return:", self.far_return)
        print("Does Not Return:", self.does_not_return)
        print("Label Not Reached:", self.label_not_reached)
        print("Custom Calling Convention:", self.custom_calling_convention)
        print("Marked As No Inline:", self.marked_as_no_inline)
        print("Has Debug Information For Optimized Code:", self.has_debug_information_for_optimized_code)

    def from_reader(self, reader):
        try:
            self.flag_byte = reader.parse_unsigned_byte_val()
            self.process_flags(self.flag_byte)
        except Exception as e:
            raise PdbException(str(e))
```

Note: The `PdbByteReader` and `PdbException` classes are not defined in the given Java code, so I did not include them in this Python translation.