Here is the equivalent Python code:

```Python
class ClangFuncNameToken:
    def __init__(self, par, hfunc):
        self.par = par
        self.hfunc = hfunc
        self.op = None

    @property
    def high_function(self):
        return self.hfunc

    @property
    def pcode_op(self):
        return self.op

    def get_min_address(self):
        if not self.op:
            return None
        return self.op.get_seqnum().get_target().physical_address()

    def get_max_address(self):
        if not self.op:
            return None
        return self.op.get_seqnum().get_target().physical_address()

    def restore_from_xml(self, el, end, pfactory):
        super.restore_from_xml(el, end, pfactory)
        opref_string = el.attribute('OPREF')
        if opref_string is not None:
            ref_id = int(opref_string)
            self.op = pfactory.get_op_ref(ref_id)

# Example usage
par = 'some value'
hfunc = 'another value'

token = ClangFuncNameToken(par, hfunc)
print(token.high_function)  # prints: another value
print(token.pcode_op)        # prints: None (initially)
```

Please note that Python does not have direct equivalent of Java's package and import statements. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass; this concept doesn't exist in Python as it uses different syntax for overriding methods.

Also, Python has no direct equivalent of Java's XML parsing functionality (`XmlElement`, `SpecXmlUtils`). You would need to use an external library like `xml.etree.ElementTree` or `lxml` if you want similar functionality.