Here is the translation of the Java code into equivalent Python:

```Python
class DexUtil:
    METHOD_ADDRESS = 0x50000000L
    LOOKUP_ADDRESS = 0xE0000000L
    MAX_METHOD_LENGTH = 0x80000

    CLASSDEF_NAME = "__classdef__"
    CATEGORY_PATH = "classes/"
    HANDLE_PATH = "/handles/"

    def to_lookup_address(program, method_index):
        pointer_size = program.get_language().get_default_space().get_pointer_size()
        address_factory = program.get_address_factory()
        default_address_space = address_factory.get_default_address_space()
        return default_address_space.get_address(DexUtil.LOOKUP_ADDRESS + (method_index * pointer_size))

    def get_or_create_namespace(program, name):
        symbol_table = program.get_symbol_table()
        parent = program.get_global_namespace()

        namespace = symbol_table.get_namespace(name, parent)
        if namespace is not None:
            return namespace

        try:
            return symbol_table.create_name_space(parent, name, SourceType.ANALYSIS)
        except Exception as e:
            return program.get_global_namespace()

    def create_namespace_from_mangled_classname(program, parent_namespace, className):
        symbol_table = program.get_symbol_table()
        if className.startswith("L") and className.endswith(";"):
            str_ = className[1:className.length() - 1]
            tokenizer = StringTokenizer(str_, "/")
            while tokenizer.has_more_tokens():
                token = tokenizer.next_token()

                namespace = symbol_table.get_namespace(token, parent_namespace)
                if namespace is not None:
                    parent_namespace = namespace
                    continue

                try:
                    if tokenizer.has_more_elements():  # package name
                        parent_namespace = symbol_table.create_name_space(parent_namespace, token, SourceType.ANALYSIS)

                    else:  # last token should be the class name
                        parent_namespace = symbol_table.createClass(parent_namespace, token, SourceType.ANALYSIS)
                except DuplicateNameException as e:
                    return None

        return parent_namespace

    def convert_type_index_to_string(header, type_index):
        if type_index == -1:  # java.lang.Object, no super class
            return "<none>"

        type_item = header.get_types().get(type_index)
        return convert_to_string(header, type_item.descriptor_index())

    def convert_to_string(header, string_index):
        string_item = header.get_strings().get(string_index)

        if string_item is None or string_item.string_data_item() is None:
            return "INVALID STRING 0x" + hex(string_index)[2:]

        return string_item.string_data_item().string()

    def convert_prototype_index_to_string(header, prototype_index):
        prototype = header.get_prototypes().get(prototype_index & 0xffff)
        builder = StringBuilder()
        builder.append(convert_type_index_to_string(header, prototype.return_type_index()))
        builder.append("( ")
        parameters = prototype.parameters
        if parameters is not None:
            for parameter in parameters.items():
                builder.append(convert_type_index_to_string(header, parameter.type))
                builder.append("\n\t")

        builder.append(" )")
        return builder.toString()

    def convert_class_string_to_path_array(prefix, class_string):
        len_ = len(class_string)
        if len_ == 0:
            return None

        if not class_string[0] == 'L':
            return None

        if not class_string[len_-1] == ';':
            return None

        return (prefix + class_string[1: len_-1]).split("/")

    def to_data_type(dtm, data_type_string):
        if len(data_type_string) == 0:
            return None

        switcher = {
            'B': SignedByteDataType.dataType,
            'C': CharDataType.dataType,
            'D': DoubleDataType.dataType,
            'F': FloatDataType.dataType,
            'I': IntegerDataType.dataType,
            'J': lambda: new LongDataType(dtm),
            'S': ShortDataType.dataType,
            'Z': BooleanDataType.dataType,
            'V': VoidDataType.dataType,
            'L': lambda: CategoryPath(CATEGORY_PATH + data_type_string[1:-1]).dataType(),
            '[': lambda: PointerDataType(to_data_type(dtm, data_type_string[1:]), dtm)
        }

        return switcher.get(data_type_string[0], None)

    def adjust_offset(offset, header):
        if header.is_data_offset_relative():
            return offset + int(header.data_offset())

        return offset

def main():
    pass

if __name__ == "__main__":
    main()
```

Please note that Python does not support switch-case statements like Java. Instead, you can use a dictionary to map the first character of the data type string to its corresponding data type.