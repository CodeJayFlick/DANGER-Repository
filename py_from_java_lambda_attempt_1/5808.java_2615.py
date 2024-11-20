Here is the translation of the given Java code into Python:

```Python
class FoundString:
    class DefinedState(enum.Enum):
        NOT_DEFINED = auto()
        DEFINED = auto()
        PARTIALLY_DEFINED = auto()
        CONFLICTS = auto()

    def __init__(self, address: 'Address', length: int, string_data_type: 'DataType', defined_state=DefinedState.NOT_DEFINED):
        self.length = length
        self.string_data_type = string_data_type
        self.address = address
        self.defined_state = defined_state

    @property
    def get_length(self) -> int:
        return self.length

    @property
    def get_address(self) -> 'Address':
        return self.address

    @property
    def get_end_address(self) -> 'Address':
        return self.address + (self.length - 1)

    def is_undefined(self) -> bool:
        return self.defined_state == FoundString.DefinedState.NOT_DEFINED

    def is_defined(self) -> bool:
        return self.defined_state == FoundString.DefinedState.DEFINED

    def is_partially_defined(self) -> bool:
        return self.defined_state == FoundString.DefinedState.PARTIALLY_DEFINED

    def conflicts(self) -> bool:
        return self.defined_state == FoundString.DefinedState.CONFLICTS

    def get_string(self, memory: 'Memory') -> str:
        membuf = DumbMemBufferImpl(memory, self.address)
        return StringDataInstance.get_string_data_instance(self.string_data_type, membuf, SettingsImpl.NO_SETTINGS, self.length).get_string_value()

    def get_data_instance(self, memory: 'Memory') -> 'StringDataInstance':
        membuf = DumbMemBufferImpl(memory, self.address)
        return StringDataInstance(self.string_data_type, SettingsImpl.NO_SETTINGS, membuf, self.length)

    def set_defined_state(self, new_state: FoundString.DefinedState):
        self.defined_state = new_state

    @property
    def get_defined_state(self) -> 'FoundString.DefinedState':
        return self.defined_state

    def is_pascall(self) -> bool:
        if isinstance(self.string_data_type, PascalStringDataType) or \
           isinstance(self.string_data_type, PascalString255DataType) or \
           isinstance(self.string_data_type, PascalUnicodeDataType):
            return True
        else:
            return False

    @property
    def get_data_type(self) -> 'DataType':
        return self.string_data_type

    def set_address(self, address: 'Address'):
        self.address = address

    def set_length(self, length: int):
        self.length = length

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other):
        if not isinstance(other, FoundString):
            return False
        return self.address == other.get_address()

    def __lt__(self, other):
        return self.address < other.get_address()

    @property
    def get_string_length(self, memory: 'Memory') -> int:
        string_data_instance = self.get_data_instance(memory)
        return string_data_instance.get_string_length()

    def __str__(self) -> str:
        return f'@{self.address}, length={self.length}, state={self.defined_state}'
```

Please note that Python does not have direct equivalent of Java's `enum` type, so I used the built-in `enum` module to create an enumeration class for the defined states.