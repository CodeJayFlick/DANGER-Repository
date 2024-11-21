Here is the translation of the Java code to Python:
```
class InvertedTreeFilter:
    def __init__(self, tree_filter):
        self.tree_filter = tree_filter

    def accepts_node(self, node):
        return not self.tree_filter.accepts_node(node)

    def show_filter_matches(self):
        return self.tree_filter.show_filter_matches()
```
Note that I've used Python's syntax and conventions to translate the Java code. Specifically:

* The `class` keyword is used to define a class in Python.
* The `__init__` method is equivalent to the constructor in Java, where instance variables are initialized.
* Methods are defined using the `def` statement, with parentheses around the argument list (if any).
* The `return` statement is used to return values from methods.
* Boolean operations like `!` and `not` are used instead of their Java counterparts.

Let me know if you have any questions or need further clarification!