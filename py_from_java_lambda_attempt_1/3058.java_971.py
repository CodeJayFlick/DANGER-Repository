Here is the translation of the given Java code into Python:

```Python
class InnerClassScript:
    def run(self):
        inner_class = MyInnerClass()
        print(inner_class.__str__())

        external_class = MyExternalClass()
        print(external_class.__str__())


class MyInnerClass:
    def __str__(self):
        return "I am an inner class."


class MyExternalClass:
    def __str__(self):
        return "I am an external class."
```

Note that Python does not have direct support for inner classes like Java. However, we can achieve similar functionality using nested classes or modules in Python.