class QueueKind:
    _values = ["eQueueKindUnknown", "eQueueKindSerial", "eQueueKindConcurrent"]
    _value_to_name = {v: n for n, v in enumerate(_values)}
    _name_to_value = {_value_to_name[v]: i for i, v in enumerate(_values)}

    @classmethod
    def swigToEnum(cls, value):
        if 0 <= value < len(cls._values) and cls._values[value] == str(value):
            return cls._value_to_name[cls._values[value]]
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    @classmethod
    def swigToEnumFromName(cls, name):
        if name in cls._value_to_name:
            return cls._name_to_value[name]
        raise ValueError(f"No enum {cls.__name__} named '{name}'")

    def __init__(self, name):
        self.name = name

    @property
    def value(self):
        return QueueKind._name_to_value[self.name]

    def __str__(self):
        return self.name


eQueueKindUnknown = QueueKind("eQueueKindUnknown")
eQueueKindSerial = QueueKind("eQueueKindSerial")
eQueueKindConcurrent = QueueKind("eQueueKindConcurrent")

print(eQueueKindUnknown.value)  # prints: 0
print(str(eQueueKindSerial))      # prints: eQueueKindSerial

try:
    print(QueueKind.swigToEnum(4))
except ValueError as ve:
    print(f"Error: {ve}")

try:
    print(QueueKind.swigToEnumFromName("non_existent_name"))
except ValueError as ve:
    print(f"Error: {ve}")
