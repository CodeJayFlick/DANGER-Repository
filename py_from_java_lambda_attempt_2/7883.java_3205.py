Here is the translation of the given Java code into equivalent Python:

```Python
class MDNestedName:
    def __init__(self):
        self.object_cpp = None
        self.mangled = ''

    def parse(self, dmang):
        if dmang.peek() != '?':
            raise MDException("Missing '?' in MDNestedName parsing")
        dmang.increment()
        begin_index = dmang.get_index()
        object_cpp = MDObjectCPP(dmang)
        object_cpp.parse()
        # MDMANG SPECIALIZATION USED.
        object_cpp = dmang.get_embedded_object(object_cpp)
        self.mangled = dmang.get_mangled_symbol()[begin_index:dmang.get_index()]

    def insert(self, builder):
        dmang.insert_string(builder, "'")
        dmang.insert_string(builder, str(self.object_cpp))
        dmang.insert_string(builder, "`")

    @property
    def mangled(self):
        return self._mangled

class MDException(Exception):
    pass
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the license information. Also, in Python, we don't need to specify types of variables like we do in Java.