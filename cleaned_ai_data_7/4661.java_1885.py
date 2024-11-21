class DWARFCompileUnit:
    def __init__(self, name: str, producer: str, comp_dir: str, low_pc: int | float, high_pc: int | float = None, language: int | float = -1, identifier_case: 'DWARFIdentifierCase' = None, has_dwo: bool = False, line: 'DWARFLine' = None):
        self.name = name
        self.producer = producer
        self.comp_dir = comp_dir
        self.low_pc = low_pc
        self.high_pc = high_pc if high_pc is not None else low_pc
        self.language = language
        self.identifier_case = identifier_case
        self.has_dwo = has_dwo
        self.line = line

    @property
    def name(self):
        return self.name

    @property
    def producer(self):
        return self.producer

    @property
    def comp_dir(self):
        return self.comp_dir

    @property
    def low_pc(self):
        return self.low_pc

    @property
    def high_pc(self):
        return self.high_pc if self.high_pc is not None else self.low_pc

    @property
    def language(self):
        return int(self.language) if self.language != -1 else -1

    @property
    def identifier_case(self):
        return self.identifier_case

    @property
    def has_dwo(self):
        return self.has_dwo

    @property
    def line(self):
        return self.line

    def get_full_file_by_index(self, index: int) -> str | None:
        if index < 0:
            raise ValueError("Negative file index was given.")
        if not hasattr(self, 'line') or self.line is None:
            return None
        return self.line.get_full_file(index, self.comp_dir)

    def get_file_by_index(self, index: int) -> str | None:
        if index < 0:
            raise ValueError("Negative file index was given.")
        if not hasattr(self, 'line') or self.line is None:
            return None
        return self.line.get_file(index, self.comp_dir)

    def __str__(self):
        return f"DWARFCompileUnit [name={self.name}, producer={self.producer}, comp_dir={self.comp_dir}, high_pc={self.high_pc}, low_pc={self.low_pc}, language={self.language}, identifier_case={self.identifier_case}, hasDWO={self.has_dwo}, line={self.line}]"
