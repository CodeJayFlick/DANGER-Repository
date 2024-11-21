Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABC, abstractmethod


class TargetDataTypeMember(ABC):
    POSITION_ATTRIBUTE_NAME = "position"
    MEMBER_NAME_ATTRIBUTE_NAME = "member_name"
    OFFSET_ATTRIBUTE_NAME = "offset"
    DATA_TYPE_ATTRIBUTE_NAME = "data_type"

    def __init__(self):
        pass

    @abstractmethod
    def get_position(self) -> int:
        return -1  # default value


class TargetDataTypeMemberImpl(TargetDataTypeMember):

    def get_position(self) -> int:
        return self.get_typed_attribute_now_by_name(POSITION_ATTRIBUTE_NAME, int)

    def get_member_name(self) -> str:
        return self.get_typed_attribute_now_by_name(MEMBER_NAME_ATTRIBUTE_NAME, str)

    def get_offset(self) -> int:
        return self.get_typed_attribute_now_by_name(OFFSET_ATTRIBUTE_NAME, int)

    def get_data_type(self) -> 'TargetDataType':
        return self.get_typed_attribute_now_by_name(DATA_TYPE_ATTRIBUTE_NAME, TargetDataType)


def main():
    pass


if __name__ == "__main__":
    main()
```

Note that Python does not have direct equivalent of Java's interfaces and abstract classes. Instead, we use ABC (Abstract Base Class) from the `abc` module to define an abstract class with abstract methods. The actual implementation is done by a subclass (`TargetDataTypeMemberImpl`).