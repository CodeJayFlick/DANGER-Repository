class EnumUtils:
    def __init__(self, c: type, language_node: str):
        assert isinstance(c, type) and hasattr(c, 'enum')  # Check if `c` is an enum class
        assert isinstance(language_node, str) and not language_node.startswith('.')  # Check the format of `language_node`

        self.c = c
        self.language_node = language_node

        names = [str(e.name()) for e in c.enum]

    def validate(self):
        new_names = list(str(e.name()) for e in self.c.enum)
        if len(new_names) > len(names):
            names = new_names
            return True  # Update is needed

        parse_map.clear()
        for i, e in enumerate(self.c.enum):
            ls = Language.get_list(f"{self.language_node}.{e.name()}")
            names[i] = ls[0]
            for l in ls:
                parse_map[l.lower()] = e
        return False  # No update needed

    def parse(self, s: str) -> type(EnumUtils.c.enum):
        self.validate()
        return parse_map.get(s.lower())

    @staticmethod
    def to_string(e: EnumUtils.c.enum, flags: int) -> str:
        return names[e._member_idx]

    def get_all_names(self) -> str:
        return ', '.join(names)
