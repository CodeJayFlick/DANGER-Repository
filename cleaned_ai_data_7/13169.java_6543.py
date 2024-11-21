class InvokeVirtual1:
    def func0_2(self, a):
        a += 1
        return

    def get_long(self):
        return 1L

    def long_and_void_test(self, a, b):
        c = a + b
        self.func0_2(c)
        d = self.get_long()
        return c + d


# Example usage:
obj = InvokeVirtual1()
print(obj.long_and_void_test(10, 20))
