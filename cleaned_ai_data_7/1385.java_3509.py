class GdbMiParser:
    UNNAMED = "<unnamed>"

    class GdbMiFieldList:
        def __init__(self, enclosed):
            self.map = MultiValuedMap()
            self.unmodifiable_map = MultiValuedMap(self.map)
            self.entry_list = []
            self.unmodifiable_entries = tuple(self.entry_list)
            self.enclosed = enclosed

        @property
        def entries(self):
            return self.unmodifiable_entries

        def add(self, key, value):
            entry = (key, value)
            self.entry_list.append(entry)
            self.map.put(key, value)

        def get(self, key):
            return self.map.get(key)

        def get_singleton(self, key):
            if not self.map.contains_key(key):
                return None
            values = list(self.map.get(key))
            if len(values) > 1:
                raise ValueError(f"Key {key} is multi-valued: {values}")
            return values[0]

        def get_string(self, key):
            value = self.get_singleton(key)
            if isinstance(value, str):
                return value
            else:
                return str(value)

        def get_list_of(self, cls, key):
            value = self.get_singleton(key)
            if isinstance(value, list) and all(isinstance(x, cls) for x in value):
                return tuple(value)
            else:
                raise ValueError(f"Key {key} is not a list of type {cls.__name__}")

        def get_field_list(self, key):
            value = self.get_singleton(key)
            if isinstance(value, GdbMiFieldList):
                return value
            elif isinstance(value, list) and all(isinstance(x, dict) for x in value):
                field_list = GdbMiFieldList(False)
                for entry in value:
                    field_list.add(**entry)
                return field_list
            else:
                raise ValueError(f"Key {key} is not a field list")

        def contains_key(self, key):
            return self.map.contains_key(key)

        @property
        def size(self):
            return len(self.entry_list)

    # see #parseString() for why this is no longer used.....
    CSTRING = None

    COMMA = r','
    LBRACKET = r'\['
    RBRACKET = r'\]'
    FIELD_ID = r'([0-9A-Za-z_]|-)+'
    EQUALS = r'=|='  # added '=' for equality operator in JSON-like strings
    LBRACE = r'{'
    RBRACE = r'}'

    def __init__(self, text):
        self.buf = iter(text)
        super().__init__()

    @property
    def cursor(self):
        return next((c for c in self.buf), None)

    def parse_object(self):
        if self.cursor == '"':
            return self.parse_string()
        elif self.cursor == '[':
            return self.parse_list()
        elif self.cursor == '{':
            return self.parse_map()
        else:
            # TODO: I'm a little uneasy about this
            # It's basically a malformed map
            return self.parse_fields(False)

    def parse_string(self):
        start = next((c for c in self.buf), None)
        if start != '"':
            raise ValueError('"', self.buf)
        end = next((c for c in self.buf), None)
        result = ''.join(c for c in self.buf)  # remove "s
        return result

    def parse_list(self):
        match(LBRACKET, True)
        result = []
        while self.cursor:
            if self.cursor == ']':
                break
            elif self.cursor == ',':
                next((c for c in self.buf), None)
            else:
                result.append(self.parse_object())
        return tuple(result)

    def parse_map(self):
        match(LBRACE, True)
        return self.parse_fields(True)

    def parse_fields(self, enclosed=False):
        if not self.cursor:
            raise ValueError("Unexpected end of input")
        start = next((c for c in self.buf), None)
        result = GdbMiFieldList(enclosed)
        while self.cursor:
            if self.cursor == ']' or self.cursor == '}':
                break
            elif self.cursor == ',':
                next((c for c in self.buf), None)
            else:
                field_id = match(FIELD_ID, True)
                match(EQUALS, True)
                result.add(field_id, self.parse_object())
        return result

    def parse(self):
        if not self.cursor:
            raise ValueError("Unexpected end of input")
        start = next((c for c in self.buf), None)
        if start == '"':
            return self.parse_string()
        elif start == '[':
            return self.parse_list()
        elif start == '{':
            return self.parse_map()
        else:
            # TODO: I'm a little uneasy about this
            # It's basically a malformed map
            return self.parse_fields(False)

    def check_empty(self, enclosed=False):
        if not self.cursor and not enclosed:
            raise ValueError("Unexpected end of input")

def match(pattern, consume=True):
    cursor = next((c for c in pattern), None)
    if cursor != next((c for c in self.buf), None):
        raise ValueError(f"Expected {pattern}, got {self.cursor}")
    if consume:
        next((c for c in self.buf), None)

def parse_object(text):
    parser = GdbMiParser(text)
    return parser.parse()

def parse_string(text):
    parser = GdbMiParser(text)
    return parser.parse_string()

def parse_fields(text, enclosed=False):
    parser = GdbMiParser(text)
    return parser.parse_fields(enclosed)
