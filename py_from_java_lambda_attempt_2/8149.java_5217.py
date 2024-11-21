Here is the equivalent Python code:

```Python
class DefinedSingleAddressRange2005MsSymbol:
    PDB_ID = 0x1134

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.bytes = reader.parse_bytes_remaining()

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: <NO API DETAILS, {len(self.bytes)} BYTES>")

    def get_symbol_type_name(self):
        return "DEFRAMGE_2005"
```

Note that Python does not have direct equivalents for Java's `public`, `private`, or `static` keywords. In Python, everything is public by default and there are no explicit access modifiers like in Java.

Also note that the equivalent of Java's `String.format()` method in Python would be using f-strings (formatted strings) which were introduced in Python 3.6. If you're using an earlier version of Python, you can use the `%` operator to format your string:

```Python
builder.append("%s: <NO API DETAILS, %d BYTES>" % (self.get_symbol_type_name(), len(self.bytes)))
```

However, f-strings are generally considered more readable and easier to work with.