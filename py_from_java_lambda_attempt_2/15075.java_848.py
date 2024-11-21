Here is the translation of the Java code to Python:

```Python
class CoffeeMakingTask:
    TIME_PER_CUP = 100

    def __init__(self, num_cups):
        super().__init__(num_cups * self.TIME_PER_CUP)

    def __str__(self):
        return f"{type(self).__name__} {super().__str__()}"
```

Note that Python does not have a direct equivalent to Java's `package` statement. In Python, you can use modules or packages to organize your code, but it is not necessary for this specific translation.

Also note that the `@Override` annotation in Java has no direct equivalent in Python. The method overriding mechanism works similarly in both languages: if you define a method with the same name and signature as one inherited from a parent class, then Python will automatically call the parent's version of the method when your own method is called.

Finally, note that `String.format()` in Java has been replaced by f-strings (`f"{...}"`) in Python.