class AbstractDBTraceSymbol:
    def __init__(self, manager: 'DBTraceSymbolManager', store: 'DBCachedObjectStore', record: 'DBRecord'):
        super().__init__(store, record)
        self.manager = manager

    def equals(self, obj):
        if not isinstance(obj, type(self)):
            return False
        if obj is self:
            return True
        that = AbstractDBTraceSymbol(obj)
        if self.get_id() == that.get_id():
            return True
        if self.get_symbol_type() != that.get_symbol_type():
            return False
        if self.name != that.name:
            return False
        if not self.address.equals(that.address):
            return False
        if not self.parent.equals(that.parent):
            return False
        return True

    def get_id(self) -> int:
        pass  # Implement this method in the subclass.

    def get_symbol_type(self) -> 'SourceType':
        pass  # Implement this method in the subclass.

    def __str__(self) -> str:
        return self.name

    @property
    def name(self):
        pass  # Implement this property getter in the subclass.

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Name must be a string.")
        self._set_name_and_source(value)

    @property
    def parent_id(self) -> int:
        pass  # Implement this property getter in the subclass.

    @parent_id.setter
    def parent_id(self, value: int):
        if not isinstance(value, int):
            raise ValueError("Parent ID must be an integer.")
        self._set_parent_and_source(value)

    @property
    def flags(self) -> int:
        pass  # Implement this property getter in the subclass.

    @flags.setter
    def flags(self, value: int):
        if not isinstance(value, int):
            raise ValueError("Flags must be an integer.")
        self._set_flags_and_source(value)

    def _set_name_and_source(self, name: str) -> None:
        pass  # Implement this method in the subclass.

    def _set_parent_and_source(self, parent_id: int) -> None:
        pass  # Implement this method in the subclass.

    def _set_flags_and_source(self, flags: int) -> None:
        pass  # Implement this method in the subclass.
