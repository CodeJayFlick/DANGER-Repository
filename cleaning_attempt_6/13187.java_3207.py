class RecursionTest:
    def triangular_numbers_int(self, n):
        if n <= 0:
            return 0
        return n + self.triangular_numbers_int(n-1)

    def triangular_numbers_long(self, l):
        if l <= 0:
            return 0
        return l + self.triangular_numbers_long(l-1)
