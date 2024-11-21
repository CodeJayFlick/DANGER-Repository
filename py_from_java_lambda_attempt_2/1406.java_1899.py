Here is a translation of the Java code into equivalent Python:

```Python
class GdbModelTargetModule:
    VISIBLE_RANGE_ATTRIBUTE_NAME = "range"
    VISIBLE_MODULE_NAME_ATTRIBUTE_NAME = "module name"

    def __init__(self, modules: dict, module):
        self.impl = modules["impl"]
        self.inferior = modules["inferior"]
        self.module = module
        self.impl.add_model_object(module, self)
        self.impl.add_model_object(module.name, self)

        self.sections = GdbModelTargetSectionContainer(self)
        self.symbols = GdbModelTargetSymbolContainer(self)

        range_ = self.do_get_range()
        self.change_attributes([], [self.sections, self.symbols], {VISIBLE_RANGE_ATTRIBUTE_NAME: range_, VISIBLE_MODULE_NAME_ATTRIBUTE_NAME: module.name})

    def init(self):
        return self.sections.request_elements(True).exceptionally(lambda ex: None)  # TODO handle exception

    @property
    def sections(self):
        return self.sections

    @property
    def symbols(self):
        return self.symbols

    def get_display(self):
        short_name = self.module.name
        sep = short_name.rfind('/')
        if sep > 0 and sep < len(short_name):
            short_name = short_name[sep + 1:]
        return short_name

    def do_get_range(self):
        base = self.module.known_base()
        max_ = self.module.known_max()
        if max_ is None:
            max_ = base
        else:
            max_ -= 1  # GDB gives end+1
        if base is None:
            addr = self.impl.space.min_address
            return AddressRangeImpl(addr, addr)
        return AddressRangeImpl(self.impl.space.get_address(base), self.impl.space.get_address(max_))

    def sections_refreshed(self):
        range_ = self.do_get_range()
        self.change_attributes([], {VISIBLE_RANGE_ATTRIBUTE_NAME: range_, RANGE_ATTRIBUTE_NAME: range_}, "Sections Refreshed")

    @property
    def range(self):
        return self.range

class AddressRangeImpl:
    def __init__(self, start, end):
        self.start = start
        self.end = end

# Note that this is a simplified translation and may not work as-is in your Python environment.
```

This code uses the same structure and naming conventions as the original Java code. It also includes some simplifications to make it more readable (e.g., using `@property` for getter methods, removing unnecessary imports).