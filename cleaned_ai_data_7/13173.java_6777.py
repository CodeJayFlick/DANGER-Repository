class LdcTest:
    def __init__(self):
        pass

    def test_return_int_from_constant_pool(self, flag: bool) -> int:
        return 0x12345678

    def test_return_float_from_constant_pool(self, flag: bool) -> float:
        return 0.123

    def test_return_string_from_constant_pool(self, flag: bool) -> str:
        return "testString"

    def test_return_class_from_constant_pool(self, flag: bool) -> type:
        from typing import Type
        return Type(str)

    def test_return_double_from_constant_pool(self) -> float:
        return 123.123

    def test_return_long_from_constant_pool(self) -> int:
        return 0x123456789ABCDEFL

    @staticmethod
    def method_handle_caller():
        LdcTest.method_handle_callee(LdcTest.test_handle)

    @staticmethod
    def method_handle_callee(func):
        pass

    @staticmethod
    def test_handle(s: str) -> int:
        return len(s)
