Here is the translation of the given Java code into Python:

```Python
class MDType:
    def __init__(self, dmang):
        self.name = ""
        super().__init__(dmang)

    def set_name(self, name: str) -> None:
        self.name = name

    def get_name(self) -> str:
        return self.name


# 20170523 attempt
class MDType:
    def __init__(self, dmang):
        self.is_array = False
        super().__init__(dmang)

    def set_is_array(self) -> None:
        self.is_array = True

    def get_is_array(self) -> bool:
        return self.is_array


# 20170412 for based5 (and probably for other)--might need to have a "referencedType"
class MDType:
    def __init__(self, dmang):
        super().__init__(dmang)
        self.is_referenced_type = False

    def set_is_referenced_type(self) -> None:
        self.is_referenced_type = True

    def get_is_referenced_type(self) -> bool:
        return self.is_referenced_type


class MDType(MDParsableItem):
    def __init__(self, dmang: MDMang):
        super().__init__(dmang)

    @staticmethod
    def parse_internal() -> None:
        pass

    def insert(self, builder: StringBuilder) -> None:
        # dmang.appendString(builder, nameModifier);
        # based.insert(builder);

    def get_type_name(self) -> str:
        return self.type_name


class MDParsableItem:
    @abstractmethod
    def parse_internal(self):
        pass

# 20170412 for based5 (and probably for other)--might need to have a "referencedType"
```

Please note that Python does not support the concept of private variables like Java. Also, there are some parts in your code which seems to be missing or unclear so I made an assumption about how they should work.