class InjectContext:
    def __init__(self):
        self.language = None
        self.base_addr = None  # Base address of op (call,userop) causing the inject
        self.next_addr = None  # Address of next instruction following the injecting instruction
        self.call_addr = None  # For a call inject, the address of the function being called
        self.ref_addr = None
        self.input_list = []  # Input parameters for the injection
        self.output = []  # Output parameters

    def restore_xml(self, xml: str) -> None:
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            if root.tag == "context":
                pass  # handle context tag here
            elif root.tag in ["input", "output"]:
                for child in root:
                    if child.tag == "addr":
                        addr = AddressXML.read_xml(child.attrib, self.base_addr)  # implement this method
                        if root.tag == "input":
                            size = int(SpecXmlUtils.decode_int(child.attrib["size"]))
                            var_node = Varnode(addr, size)
                            self.input_list.append(var_node)
                        elif root.tag == "output":
                            size = int(SpecXmlUtils.decode_int(child.attrib["size"]))
                            var_node = Varnode(addr, size)
                            self.output.append(var_node)

        except ET.ParseError as e:
            raise PcodeXMLException("Problem parsing inject context: {}".format(e))

class Handler(ET._ElementTreeHandler):
    def __init__(self, addr_factory):
        super().__init__()
        self.addr_factory = addr_factory
        self.state = 0

    def start(self, elem):
        if elem.tag == "context":
            self.state = 1
        elif elem.tag in ["input", "output"]:
            self.input_list = []
            self.output = []
            self.state = 3
        elif elem.tag == "addr":
            addr = AddressXML.read_xml(elem.attrib, self.addr_factory)
            if self.state == 1:
                self.base_addr = addr
                self.state = 2
            elif self.state == 2:
                self.call_addr = addr
            elif self.state == 3 or self.state == 4:
                size = int(SpecXmlUtils.decode_int(elem.attrib["size"]))
                var_node = Varnode(addr, size)
                if self.state == 3:
                    self.input_list.append(var_node)
                else:  # state == 4
                    self.output.append(var_node)

        elif elem.tag not in ["context", "input", "output", "addr"]:
            raise ET.ParseError("Unrecognized inject tag: {}".format(elem.tag))

class Varnode:
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size

class PcodeXMLException(Exception):
    pass

class AddressXML:
    @staticmethod
    def read_xml(tag, attrib, addr_factory) -> None:
        # implement this method
        return None  # replace with actual implementation

class SpecXmlUtils:
    @staticmethod
    def decode_int(s: str) -> int:
        try:
            return int(s)
        except ValueError as e:
            raise PcodeXMLException("Invalid size value: {}".format(e))
