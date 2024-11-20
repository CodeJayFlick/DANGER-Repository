Here is the translation of the given Java code into Python:

```Python
class BindState:
    def __init__(self, header, program):
        self.header = header
        self.program = program
        self.weak = False

    def print(self):
        section_address = self.get_address()
        
        for section in self.header.get_all_sections():
            if section_address.offset >= section.address and section_address.offset < (section.address + section.size):
                return f"{self.get_segment_name()}  {section.name}  {section_address}  {'weak' if self.weak else 'normal'}"

    def set_weak(self, weak):
        self.weak = weak

class MachHeader:
    def __init__(self):
        pass
    
    def get_all_sections(self):
        return []

class Section:
    def __init__(self, name):
        self.name = name
        self.address = 0
        self.size = 0

class Address:
    def __init__(self, offset=0):
        self.offset = offset

# Example usage:

mach_header = MachHeader()
sections = [Section("section1"), Section("section2")]
for section in sections:
    mach_header.get_all_sections().append(section)

program = None
bind_state = BindState(mach_header, program)
print(bind_state.print())
```

Please note that the `MachHeader`, `Section` and `Address` classes are not part of Python's standard library. They were added here to mimic the Java code as closely as possible.