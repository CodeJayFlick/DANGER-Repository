Here is the translation of the Java code to Python:
```
import math

class UDTFExp:
    def set_transformer(self):
        self.transformer = lambda x: math.exp(x)

# Example usage
udtf_exp = UDTFExp()
print(udtf_exp.set_transformer())  # prints a function that applies exp() to its input
```
Note that in Python, we don't need to declare the type of variables or methods like we do in Java. Also, the `@Override` annotation is not necessary in Python since method overriding works differently than it does in Java.

The `set_transformer()` method simply assigns a lambda function (an anonymous function) to an instance variable called `transformer`. The lambda function takes one argument and returns its exponential value using the `math.exp()` function.