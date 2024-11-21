Here is the translation of the given Java code into Python:

```Python
class BlockGraph:
    def __init__(self):
        self.list = []  # List of blocks within the super-block
        self.maxindex = -1  # max-index contains minimum max

    def add_block(self, bl: 'PcodeBlock'):
        if isinstance(bl, BlockGraph):
            min_val, max_val = bl.index, bl.maxindex
        else:
            min_val, max_val = bl.index, bl.index
        
        if not self.list:
            self.index = min_val
            self.maxindex = max_val
        else:
            if min_val < self.index:
                self.index = min_val
            if max_val > self.maxindex:
                self.maxindex = max_val

        bl.parent = self
        self.list.append(bl)

    def set_indices(self):
        for i in range(len(self.list)):
            block = self.list[i]
            block.index = i
        self.index = 0
        self.maxindex = len(self.list) - 1

    @property
    def size(self):
        return len(self.list)

    def get_block(self, i: int):
        return self.list[i]

    def add_edge(self, begin: 'PcodeBlock', end: 'PcodeBlock'):
        end.add_in_edge(begin, 0)

    def transfer_object_ref(self, ingraph: 'BlockGraph'):
        queue = []
        pos = 0
        queue.append(self)
        while pos < len(queue):
            curgraph = queue[pos]
            pos += 1
            for i in range(len(curgraph.list)):
                block = curgraph.get_block(i)
                if isinstance(block, BlockCopy):
                    copyblock = block
                    altindex = copyblock.alt_index
                    if altindex < ingraph.size:
                        block2 = ingraph.get_block(altindex)
                        if isinstance(block2, BlockCopy):
                            copyblock.set(copyblock.ref, copyblock.start)  # Transfer the object reference
                elif isinstance(block, BlockGraph):
                    queue.append(block)

    def save_xml_body(self, writer: 'Writer'):
        super().save_xml_body(writer)
        for i in range(len(self.list)):
            block = self.list[i]
            buf = StringBuilder()
            buf.append("<bhead")
            SpecXmlUtils.encode_signed_integer_attribute(buf, "index", block.index)
            name = PcodeBlock.type_to_name(block.blocktype)
            SpecXmlUtils.encode_string_attribute(buf, "type", name)
            buf.append("/>\n")
            writer.write(str(buf))
        for i in range(len(self.list)):
            block = self.list[i]
            block.save_xml(writer)

    def restore_xml_body(self, parser: 'XmlPullParser', resolver: 'BlockMap'):
        new_resolver = BlockMap(resolver)
        super().restore_xml_body(parser, new_resolver)
        tmplist = []
        while parser.peek().is_start():
            if not parser.peek().get_name().equals("bhead"):
                break
            el = parser.start()
            ind = SpecXmlUtils.decode_int(el.get_attribute("index"))
            name = el.get_attribute("type")
            newbl = new_resolver.create_block(name, ind)
            tmplist.append(newbl)
            parser.end(el)

        new_resolver.sort_level_list()
        for i in range(len(tmplist)):
            bl = tmplist[i]
            bl.restore_xml(parser, new_resolver)
            self.add_block(bl)

    def restore_xml(self, parser: 'XmlPullParser', factory: 'AddressFactory'):
        resolver = BlockMap(factory)
        self.restore_xml_body(parser, resolver)
        resolver.resolve_goto_references()

class PcodeBlock:
    GRAPH = "GRAPH"

    def __init__(self):
        pass

    @property
    def blocktype(self) -> str:
        return ""

    def save_xml(self, writer: 'Writer'):
        pass

    def restore_xml(self, parser: 'XmlPullParser', resolver: 'BlockMap'):
        pass


class BlockCopy(PcodeBlock):
    def __init__(self):
        super().__init__()
        self.alt_index = -1
        self.ref = None
        self.start = None

    @property
    def alt_index(self) -> int:
        return self.alt_index

    @alt_index.setter
    def alt_index(self, value: int):
        self.alt_index = value


class BlockMap:
    def __init__(self, factory: 'AddressFactory'):
        super().__init__()
        self.factory = factory
        self.level_list = []

    def create_block(self, name: str, index: int) -> 'PcodeBlock':
        pass

    @property
    def level_list(self):
        return self.level_list


class XmlPullParser:
    def __init__(self):
        super().__init__()

    def peek(self) -> object:
        pass

    def start(self) -> object:
        pass

    def end(self, el: object):
        pass

    @property
    def name(self) -> str:
        return ""

    def get_attribute(self, attribute_name: str) -> str:
        pass


class Writer:
    def __init__(self):
        super().__init__()

    def write(self, text: str):
        pass
```

Please note that the above Python code is a direct translation of the given Java code and may not be perfect. It might require some adjustments to work correctly in your specific use case.