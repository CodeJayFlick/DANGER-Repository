class Symbol:
    def __init__(self):
        self.name = None
        self.id = 0  # Unique id across all symbols
        self.scope_id = 0  # id of scope this symbol is in

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def scope_id(self):
        return self._scope_id

    @scope_id.setter
    def scope_id(self, value):
        self._scope_id = value

    def restore_header_xml(self, parser):
        el = parser.start()
        self.name = el.get("name")
        self.id = int(el.get("id"))
        self.scope_id = int(el.get("scope"))
        parser.end(el)

    def restore_xml(self, parser, sleigh_language) -> None:
        raise NotImplementedError  # Always overridden by subclass
