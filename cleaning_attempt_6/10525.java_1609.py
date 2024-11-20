class MathUtilities:
    def __init__(self):
        pass

    @staticmethod
    def unsigned_divide(numerator: int, denominator: int) -> int:
        if denominator < 0:
            raise ValueError("denominator too big")
        if numerator >= 0:
            return numerator // denominator
        numerator_div2 = numerator >> 1
        result = (numerator_div2 // denominator) << 1
        remainder = (numerator_div2 % denominator) << 1
        remainder += numerator & 1
        if remainder >= denominator:
            result += 1
        return result

    @staticmethod
    def unsigned_modulo(numerator: int, denominator: int) -> int:
        if denominator < 0:
            raise ValueError("denominator too big")
        if numerator >= 0:
            return numerator % denominator
        numerator_div2 = numerator >> 1
        remainder = (numerator_div2 % denominator) << 1
        remainder += numerator & 1
        return remainder % denominator

    @staticmethod
    def clamp(value: int, min_value: int, max_value: int) -> int:
        if value < min_value:
            return min_value
        elif value > max_value:
            return max_value
        else:
            return value

    @staticmethod
    def unsigned_min(a: int, b: int) -> int:
        return a if a <= b else b

    @staticmethod
    def unsigned_max(a: int, b: int) -> int:
        return a if a >= b else b


def main():
    d = 4
    for i in range(-27, 28):
        result = MathUtilities.unsigned_divide(i, d)
        mod = MathUtilities.unsigned_modulo(i, d)
        v = (result * d) + mod
        print(f"0x{i:016X} -> 0x{result:08X}:0x{mod:08X} -> 0x{v:08X}")


if __name__ == "__main__":
    main()
