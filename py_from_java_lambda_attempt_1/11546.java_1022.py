Here is the translation of the Java code to Python:

```Python
class ConstructTpl:
    def __init__(self):
        self.numlabels = 0
        self.vec = []
        self.result = None

    @classmethod
    def from_xml(cls, parser, factory):
        sectionid = -1
        el = parser.get_current_element()
        if 'labels' in el.attrib:
            numlabels = int(el.attrib['labels'])
        if 'section' in el.attrib:
            sectionid = int(el.attrib['section'])
        handel = parser.peek()
        if handel.name == "null":
            result = None
            parser.discard_subtree()
        else:
            result = HandleTpl()
            result.from_xml(parser, factory)
        oplist = []
        while not parser.is_end():
            op = OpTpl()
            op.from_xml(parser, factory)
            oplist.append(op)
        vec = [op for op in oplist]
        return sectionid

    def get_num_labels(self):
        return self.numlabels

    def get_op_vec(self):
        return self.vec

    def get_result(self):
        return self.result


class OpTpl:
    pass


class HandleTpl:
    pass
```

Please note that I did not implement the `OpTpl` and `HandleTpl` classes as they were missing in your Java code. You would need to define these classes based on their usage in the original Java code.