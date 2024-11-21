class AddressUtils:
    @staticmethod
    def unsigned_compare(v1: int, v2: int) -> int:
        if v1 == v2:
            return 0
        elif (v1 >= 0 and v2 >= 0):
            return -1 if v1 < v2 else 1
        elif (v1 < 0 and v2 < 0):
            return -1 if v1 < v2 else 1
        elif v1 < 0:
            return 1
        else:
            return -1

    @staticmethod
    def unsigned_subtract(a: int, b: int) -> int:
        return a - b

    @staticmethod
    def unsigned_add(a: int, b: int) -> int:
        return a + b
