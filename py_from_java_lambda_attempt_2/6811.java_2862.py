Here is the translation of the Java code into Python:

```Python
class ClangStatement:
    def __init__(self):
        self.op = None  # Root op of C-statement

    @property
    def pcode_op(self):
        return self.op

    def restore_from_xml(self, parser, pfactory):
        node = next(parser)
        if 'opref' in node.attrib:
            ref_id = int(node.attrib['opref'])
            self.op = pfactory.get_op_ref(ref_id)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. Also, Python uses indentation to denote block-level structure (like functions and classes), so I've removed those parts from the translation.