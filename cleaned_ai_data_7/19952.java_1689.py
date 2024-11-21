class SoundUtils:
    def __init__(self):
        pass  # equivalent to private constructor in Java

    @staticmethod
    def parse(s: str) -> 'Sound':
        return EnumUtils.parse(Sound, s)

    @staticmethod
    def to_string(sound: 'Sound', flags: int) -> str:
        return EnumUtils.to_string(sound, flags)

    @staticmethod
    def get_all_names() -> str:
        return EnumUtils.get_all_names()

class EnumUtils:
    def __init__(self):
        pass  # equivalent to constructor in Java

    @classmethod
    def parse(cls: type['EnumUtils'], enum_type: type, s: str) -> 'enum_type':
        raise NotImplementedError("parse method not implemented")

    @classmethod
    def to_string(cls: type['EnumUtils'], enum_value: object, flags: int) -> str:
        raise NotImplementedError("to_string method not implemented")

    @classmethod
    def get_all_names(cls: type['EnumUtils']) -> str:
        raise NotImplementedError("get_all_names method not implemented")
