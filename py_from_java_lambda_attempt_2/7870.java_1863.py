Here is the translation of the Java code into Python:

```Python
class MDFuzzyFit:
    def __init__(self):
        self.class_list = [MDType(), MDDataType(), MDFunctionType()]

    def fuzz(self, mangled_arg: str) -> bool:
        if not mangled_arg:
            return False

        output_builder = StringBuilder()
        dmang = MDMang()

        for offset in range(len(mangled_arg), -1, -1):
            substring = mangled_arg[offset:]
            try:
                dmang.set_mangled_symbol(substring)
                dmang.push_context()
                num_chars_remaining = len(substring)

                for cls in self.class_list:
                    item = create_item(cls, dmang)
                    if not isinstance(item, MDParsableItem):
                        continue

                    item.parse()
                    output_builder.append(f"Offset: {offset}; Class: {cls.__name__}; Output:{item.insert()}")

            except MDException as e:
                print(e)

        return True

    def get_best_type_info_location(self, mangled_arg: str) -> int:
        dmang = MDMang()
        offset = len(mangled_arg)
        best_offset = offset
        highest = False

        while offset > 0:
            try:
                substring = mangled_arg[offset-1:]
                dmang.set_mangled_symbol(substring)
                dmang.push_context()

                type_info = MDTypeInfoParser.parse(dmang, -1)
                if not isinstance(type_info, MDTypeInfo):
                    continue

                num_chars_remaining = len(substring)

                if num_chars_remaining == 0:
                    best_offset = offset
            except (MDException, Exception) as e:
                print(e)

        return best_offset

    def get_best_type_location(self, mangled_arg: str) -> int:
        dmang = MDMang()
        offset = len(mangled_arg)
        best_offset = offset

        while offset > 0:
            try:
                substring = mangled_arg[offset-1:]
                dmang.set_manged_symbol(substring)
                dmang.push_context()

                type_info = MDDataTypeParser.parse_type(dmang, highest=True)
                if not isinstance(type_info, MDTypeInfo):
                    continue

                num_chars_remaining = len(substring)

                if num_chars_remaining == 0:
                    best_offset = offset
            except (MDException, Exception) as e:
                print(e)

        return best_offset

    def create_item(self, cls: type, dmang: MDMang) -> MDParsableItem:
        try:
            constructor = cls.__init__(cls)
            item = constructor(dmang)
            if not isinstance(item, MDParsableItem):
                raise MDException("Cannot create new instance of " + str(cls))
            return item
        except (SecurityError, NoMethodFound) as e:
            print(e)

class StringBuilder:
    def __init__(self):
        self.builder = ""

    def append(self, string: str):
        self.builder += string

    def toString(self) -> str:
        return self.builder


# Usage example:

mfd = MDFuzzyFit()
print(mfd.fuzz("your_mangled_string"))
```

Please note that Python does not have direct equivalent of Java's `StringBuilder` class. I used a simple class to mimic its functionality.

Also, please replace `"your_mangled_string"` with your actual mangled string when calling the `fuzz()` method.