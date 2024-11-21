class DataTypeDisplayOptions:
    MAX_LABEL_STRING_LENGTH = 32

    DEFAULT = type("DEFAULT", (object,), {
        "use_abbreviated_form": lambda self: False,
        "get_label_string_length": lambda self: MAX_LABEL_STRING_LENGTH
    })

    def __init__(self):
        pass

    def use_abbreviated_form(self) -> bool:
        return False

    def get_label_string_length(self) -> int:
        return DataTypeDisplayOptions.MAX_LABEL_STRING_LENGTH


# Note that in Python, we don't need to define the methods as static
class DefaultDataTypeDisplayOptions(DataTypeDisplayOptions):
    pass
