Here is the translation of the given Java code into Python:

```Python
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
```

Please note that Python does not have a direct equivalent to Java's `public` keyword. In Python, access modifiers like public are implicit and do not need to be specified explicitly.