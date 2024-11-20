class ScalarToLongColumnTypeMapper:
    def convert(self, scalar: 'Scalar') -> int:
        return scalar.get_value()
