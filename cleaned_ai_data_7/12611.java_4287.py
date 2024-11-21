class BlockGoto:
    def __init__(self):
        self.gototarget = None
        self.gototype = 1
        self.blocktype = "GOTO"

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
        self._gototype = value

    def save_xml_body(self, writer):
        super().save_xml_body(writer)
        buf = StringBuilder()
        buf.append("<target")
        leaf = self.gototarget.get_front_leaf()
        depth = self.gototarget.calc_depth(leaf)
        buf.append(f" index='{leaf.index}'")
        buf.append(f" depth={depth}")
        buf.append(f" type={self.gototype}")
        buf.append("/>\n")
        writer.write(buf.toString())

    def restore_xml_body(self, parser, resolver):
        super().restore_xml_body(parser, resolver)
        el = parser.start("target")
        target = int(el.get_attribute("index"))
        depth = int(el.get_attribute("depth"))
        self.gototype = int(el.get_attribute("type"))
        parser.end(el)
        resolver.add_goto_ref(self, target, depth)

class PcodeBlock:
    def __init__(self):
        pass

    @property
    def front_leaf(self):
        return None  # Replace with actual implementation

    def calc_depth(self, leaf):
        return None  # Replace with actual implementation

    @property
    def index(self):
        return None  # Replace with actual implementation

class BlockMap:
    def __init__(self):
        pass

    def add_goto_ref(self, blockgoto, target, depth):
        pass  # Replace with actual implementation

class PcodeXMLException(Exception):
    pass
