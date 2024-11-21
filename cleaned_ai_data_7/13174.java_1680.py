class LocalVariableTests:
    def boolean_test(self, a: bool, b: bool) -> bool:
        one = a
        two = b
        return one or two

    def byte_test(self, a: int, b: int) -> int:
        one = a
        two = b
        return one + two

    def char_test(self, a: str, b: str) -> str:
        one = a
        two = b
        return chr(ord(one) + ord(two))

    def short_test(self, a: int, b: int) -> int:
        one = a
        two = b
        return one + two

    def int_test(self, a: int, b: int) -> int:
        one = a
        two = b
        sum = one + two
        if sum % 2 == 0:
            return 1
        else:
            return one + two

    def float_test(self, a: float, b: float) -> float:
        one = a
        two = b
        return one + two

    def ref_test(self, a: int, b: int) -> int:
        one = a
        two = b
        return one + two

    def long_test(self, a: int, b: int) -> int:
        one = a
        two = b
        return one + two

    def double_test(self, a: float, b: float) -> float:
        one = a
        two = b
        return one + two


# Example usage:
test_obj = LocalVariableTests()
print(test_obj.boolean_test(True, False))  # Output: True
print(test_obj.byte_test(1, 2))             # Output: 3
print(test_obj.char_test('a', 'b'))         # Output: '\xc2\xb3'
print(test_obj.short_test(1, 2))            # Output: 3
print(test_obj.int_test(1, 2))              # Output: 3 (or 4 if sum is even)
print(test_obj.float_test(1.0, 2.0))        # Output: 3.0
print(test_obj.ref_test(1, 2))              # Output: 3
print(test_obj.long_test(1, 2))             # Output: 3
print(test_obj.double_test(1.0, 2.0))       # Output: 3.0
