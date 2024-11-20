class UseropSymbol:
    def __init__(self):
        self.index = None  # Unique id for this userop

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, value):
        self._index = value

    def restore_xml(self, parser, sleigh_language):
        el = parser.get_start_tag("userop")
        if "index" in el.attrib:
            self.index = int(el.attrib["index"])
