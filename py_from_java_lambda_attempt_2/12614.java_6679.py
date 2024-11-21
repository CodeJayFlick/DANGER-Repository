Here is the translation of the Java code into Python:

```Python
class BlockIfGoto:
    def __init__(self):
        self.gototarget = None
        self.gototype = 1
    
    @property
    def gototarget(self):
        return self._gototarget
    
    @gototarget.setter
    def gototarget(self, value):
        self._gototarget = value

    @property
    def gototype(self):
        return self._gototype
    
    @gototype.setter
    def gototype(self, value):
        if not isinstance(value, int) or value < 1:
            raise ValueError("Goto type must be an integer greater than zero")
        self._gototype = value

    def save_xml_body(self, writer):
        super().save_xml_body(writer)
        leaf = self.gototarget.get_front_leaf()
        depth = self.gototarget.calc_depth(leaf)
        buf = StringBuilder("target ")
        buf.append(f"index='{self.gototarget.getIndex()}'")
        buf.append(f"depth={depth}")
        buf.append(f"type={self.gototype}")
        writer.write(buf.toString())
    
    def restore_xml_body(self, parser, resolver):
        super().restore_xml_body(parser, resolver)
        el = parser.start("target")
        self.gototype = int(el.getAttribute("type"))
        target = int(el.getAttribute("index"))
        depth = int(el.getAttribute("depth"))
        parser.end(el)
        if not hasattr(resolver, "add_goto_ref"):
            raise AttributeError("Resolver must have an add_goto_ref method")
        resolver.add_goto_ref(self, target, depth)

class BlockGraph:
    def save_xml_body(self, writer):
        pass
    
    def restore_xml_body(self, parser, resolver):
        pass

class PcodeBlock:
    @property
    def front_leaf(self):
        return None
    
    def calc_depth(self, leaf):
        return 0
    
    @property
    def getIndex(self):
        return None
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.