Here is the equivalent Python code:

```Python
class DWARFForm:
    def __init__(self, value):
        self.value = value

DWARF_FORMS = {
    0x0: 'NULL',
    0x1: 'DW_ FORM_addr',
    0x3: 'DW_ FORM_block2',
    0x4: 'DW_ FORM_block4',
    0x5: 'DW_ FORM_data2',
    0x6: 'DW_ FORM_data4',
    0x7: 'DW_ FORM_data8',
    0x8: 'DW_ FORM_string',
    0x9: 'DW_ FORM_block',
    0xa: 'DW_ FORM_block1',
    0xb: 'DW_ FORM_data1',
    0xc: 'DW_ FORM_flag',
    0xd: 'DW_ FORM_sdata',
    0xe: 'DW_ FORM_strp',
    0xf: 'DW_ FORM_udata',
    0x10: 'DW_ FORM_ref_addr',
    0x11: 'DW_ FORM_ref1',
    0x12: 'DW_ FORM_ref2',
    0x13: 'DW_ FORM_ref4',
    0x14: 'DW_ FORM_ref8',
    0x15: 'DW_ FORM_ref_udata',
    0x16: 'DW_ FORM_indirect',
    0x17: 'DW_ FORM_sec_offset',
    0x18: 'DW_ FORM_exprloc',
    0x19: 'DW_ FORM_flag_present',
    0x20: 'DW_ FORM_ref_sig8'
}

def get_value(self):
    return self.value

@classmethod
def find(cls, key):
    if value := DWARF_FORMS.get(key):
        return cls(value)
    raise ValueError(f"Invalid Integer value: {key}")

# Example usage:
dwarf_form = DWARFForm(0x1)  # Create a new instance with the given value
print(dwarf_form.value)  # Print the value of the enum

found_dwarf_form = DWARFForm.find(0x5)  # Find and return an existing enum
if found_dwarf_form:
    print(found_dwarf_form.value)
else:
    print("Enum not found")
```

This Python code defines a class `DWARFForm` with the same properties as the Java code. The dictionary `DWARF_FORMS` maps integer values to their corresponding string representations, which is used in the `find` method to look up an enum value given its key.