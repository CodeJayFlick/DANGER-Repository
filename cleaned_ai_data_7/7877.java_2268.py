class MDParsableItem:
    def __init__(self, dmang):
        self.dmang = dmang

    @property
    def dmang(self):
        return self._dmang

    @dmang.setter
    def dmang(self, value):
        self._dmang = value

    _startIndexOffset = 0

    @property
    def startIndexOffset(self):
        return self._startIndexOffset

    @startIndexOffset.setter
    def startIndexOffset(self, value):
        self._startIndexOffset = value

    def __init__(self, dmang, startIndexOffset=0):
        super().__init__(dmang)
        self.startIndexOffset = startIndexOffset

    def parse(self):
        try:
            self.dmang.parse_info_push(self.startIndexOffset, type(self).__name__)
            self._parse_internal()
            self.dmang.parse_info_pop()
        except Exception as e:
            raise MDException(str(e))

    @abstractmethod
    def _parse_internal(self):
        pass

    def insert(self, builder: str) -> None:
        # Derived classes have contents. Base contents could be added here.
        pass

    def append(self, builder: str) -> None:
        # Derived classes have contents. Base contents could be added here.
        pass

    def __str__(self):
        try:
            builder = StringBuilder()
            self.insert(builder)
            self.dmang.clean_output(builder)
            return builder.toString()
        except Exception as e:
            raise MDException(str(e))
