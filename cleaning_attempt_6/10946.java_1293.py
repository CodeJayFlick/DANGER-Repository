class InvalidHREFLink:
    def __init__(self, href: 'help.validator.model.HREF', message: str):
        self.href = href
        self.message = message
        if os.environ.get('GHIDRA_HELP_FAILFAST') == 'True':
            raise RuntimeError(f"{message}: {href}")

    @property
    def href(self) -> 'help.validator.model.HREF':
        return self._href

    @href.setter
    def href(self, value: 'help.validator.model.HREF'):
        self._href = value

    @property
    def message(self) -> str:
        return self._message

    @message.setter
    def message(self, value: str):
        self._message = value

    def identity_hash_code(self) -> int:
        return hash(self.href)

    def get_source_file(self) -> 'pathlib.Path':
        return self.href.get_source_file()

    def get_line_number(self) -> int:
        return self.href.get_line_number()

    def compare_to(self, other: 'help.validator.links.InvalidLink') -> int:
        if not isinstance(other, InvalidHREFLink):
            return 1
        other_link = other
        result = type(self).__name__.casefold().compare_to(type(other_link).__name__.casefold())
        if result != 0:
            return -result
        return self.href.compare_to(other_link.href)

    def __str__(self) -> str:
        #return f"{self.message}\n\tlink: {self.href}"  # sourceFileInfo is missing here
        return f"{self.message}\n\tlink: {self.href}"

    def hash(self) -> int:
        prime = 31
        result = 1
        if self.href is not None:
            result *= prime + hash(self.href)
        if self.message is not None:
            result *= prime + hash(self.message)
        return result

    def __eq__(self, other: object) -> bool:
        if self == other:
            return True
        if other is None or type(self).__name__ != str(type(other)):
            return False
        other_link = other
        if self.href is not None and other_link.href is not None:
            if self.href != other_link.href:
                return False
        elif (self.href is None) ^ (other_link.href is None):
            return False
        if self.message is not None and other_link.message is not None:
            if self.message != other_link.message:
                return False
        elif (self.message is None) ^ (other_link.message is None):
            return False
        return True

    def __hash__(self) -> int:
        prime = 31
        result = 1
        if self.href is not None:
            result *= prime + hash(self.href)
        if self.message is not None:
            result *= prime + hash(self.message)
        return result
