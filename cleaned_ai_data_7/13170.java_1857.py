class InvokeVirtual2:
    def func2_2(self, a):
        return a + 1
    
    def func2_2_2(self, a, b):
        return a + b

    def longTest2(self, a, b):
       c = self.func2_2(a)
       d = self.func2_2(b)
       e = self.func2_2_2(c,d)
       return e + 1


# Create an instance of the class
iv = InvokeVirtual2()

print(iv.longTest2(5,6))
