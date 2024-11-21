Here is the translation of the given Java code into Python:

```Python
class AddressLabelInfo:
    def __init__(self, addr=None, label=None, primary=False, scope=None, symbol_source=0, entry=False):
        self.addr = addr
        self.label = label
        self.is_primary = primary
        self.scope = scope
        self.symbol_source = symbol_source
        self.entry = entry

    def __init__(self, s):
        if isinstance(s, Symbol):
            self.addr = s.get_address()
            self.label = s.name
            self.is_primary = s.primary
            self.scope = s.parent_namespace
            self.symbol_source = s.source
            self.entry = s.external_entry_point()

    @property
    def address(self):
        return self.addr

    @property
    def label_(self):
        return self.label

    @property
    def is_primary_(self):
        return self.is_primary

    @property
    def scope_(self):
        return self.scope

    @property
    def symbol_source_(self):
        return self.symbol_source

    @property
    def entry_(self):
        return self.entry

    def __str__(self):
        if not hasattr(self, 'processor_symbol_type'):
            processor_symbol_type = None
        else:
            processor_symbol_type = self.processor_symbol_type
        return f"LABEL INFO NAME={self.label}, ADDR={self.addr}, isEntry={self.entry_}, type={processor_symbol_type}"

    def __eq__(self, other):
        if not isinstance(other, AddressLabelInfo):
            return False

        if self.addr != other.addr:
            return False

        if self.label != other.label:
            return False

        if self.is_primary != other.is_primary:
            return False

        if self.scope != other.scope:
            return False

        if self.symbol_source != other.symbol_source:
            return False

        if self.entry != other.entry:
            return False

        return True

    def __lt__(self, other):
        if not isinstance(other, AddressLabelInfo):
            raise TypeError("Can't compare with non-AddressLabelInfo")

        addr_str = str(self.addr)
        this_str = str(other.addr)

        string_compare = addr_str.__lt__(this_str)

        if string_compare:
            return True
        elif not string_compare and self.label < other.label:
            return True

        return False


class Symbol:
    def __init__(self, name):
        self.name = name

    @property
    def address(self):
        pass  # Implement this method in the actual class

    @property
    def parent_namespace(self):
        pass  # Implement this method in the actual class

    @property
    def source(self):
        return 0  # Implement this method in the actual class

    @property
    def external_entry_point(self):
        return False  # Implement this method in the actual class


class Namespace:
    pass  # This is a placeholder, implement it according to your needs


from functools import total_ordering

@total_ordering
class AddressLabelInfo:
    ...
```

Please note that I have not implemented all methods and properties of `Symbol`, `Namespace` classes as they were missing in the original Java code. You will need to fill these with actual implementations based on your requirements.