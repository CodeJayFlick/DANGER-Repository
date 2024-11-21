class AbstractFieldListMsType:
    def __init__(self):
        self.base_class_list = []
        self.member_list = []
        self.method_list = []
        self.index_list = []

    def add_base_class(self, type):
        self.base_class_list.append(type)

    def add_member(self, type):
        self.member_list.append(type)

    def add_method(self, type):
        self.method_list.append(type)

    def add_index(self, index_type):
        self.index_list.append(index_type)

    @property
    def base_class_list(self):
        return self.base_class_list

    @base_class_list.getter
    def get_base_class_list(self):
        return self.base_class_list

    @property
    def member_list(self):
        return self.member_list

    @member_list.getter
    def get_member_list(self):
        return self.member_list

    @property
    def method_list(self):
        return self.method_list

    @method_list.getter
    def get_method_list(self):
        return self.method_list

    @property
    def index_list(self):
        return self.index_list

    @index_list.getter
    def get_index_list(self):
        return self.index_list

    def emit(self, builder, bind):
        class_builder = StringBuilder()
        ds_bases = DelimiterState("  : ", ", ")
        for type in self.base_class_list:
            class_builder.append(ds_bases.out(True, str(type)))

        member_builder = StringBuilder()
        member_builder.append(" {")
        ds_members = DelimiterState("", ",")
        for type in self.member_list:
            member_builder.append(ds_members.out(True, str(type)))
        member_builder.append("}")

        other_builder = StringBuilder()
        if len(self.method_list) != 0:
            other_builder.append("...")
        builder.append(class_builder)
        builder.append(member_builder)
        builder.append(other_builder)


class DelimiterState:
    def __init__(self, delimiter, separator):
        self.delimiter = delimiter
        self.separator = separator

    @property
    def out(self, first_line, value):
        if not first_line and self.delimiter == "":
            return ""
        elif first_line or self.delimiter != "  : ":
            return f"{self.delimiter}{value}"
        else:
            return f" {value}"


class StringBuilder:
    def __init__(self):
        self.value = ""

    @property
    def value(self):
        return self.value

    @value.setter
    def append(self, value):
        if isinstance(value, str):
            self.value += value
        elif hasattr(value, "append"):
            while True:
                try:
                    getattr(value, "append")(self)
                    break
                except AttributeError as e:
                    print(f"Error: {e}")
