Here is the translation of the Java code to Python:
```
class ScalarToLongColumnTypeMapper:
    def convert(self, scalar: 'Scalar') -> int:
        return scalar.get_value()
```
Note that I used type hints for the `scalar` parameter and the return value, but this is not strictly necessary in Python. The translation was straightforward, with some minor adjustments to fit the syntax of the two languages.

Here's a brief explanation:

* In Java, we have a class named `ScalarToLongColumnTypeMapper` that extends another class (`ColumnTypeMapper`). In Python, we define a simple class without inheritance.
* The `convert` method in Java takes an argument of type `Scalar` and returns a value of type `Long`. In Python, the equivalent method takes an argument of type `scalar` (note the single quotes) and returns an integer value (`int`) using the `.get_value()` method on the `scalar` object.
* The rest of the code is just boilerplate comments that are not translated to Python.