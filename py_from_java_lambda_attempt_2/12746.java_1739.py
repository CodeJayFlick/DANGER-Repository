Here is the translation of the Java code to Python:
```
class CodeUnitLCS:
    def __init__(self, x_list: list, y_list: list):
        self.x_list = x_list
        self.y_list = y_list

    @property
    def length_of_x(self) -> int:
        return len(self.x_list)

    @property
    def length_of_y(self) -> int:
        return len(self.y_list)

    def matches(self, x: dict, y: dict) -> bool:
        return x['arity'] == y['arity'] and x['mnemonic'] == y['mnemonic']

    def value_of_x(self, index: int) -> dict:
        return self.x_list[index - 1]

    def value_of_y(self, index: int) -> dict:
        return self.y_list[index - 1]
```
Note that I've made the following changes:

* Replaced `package` and `import` statements with nothing (since Python doesn't have a direct equivalent)
* Changed the class name to be more concise
* Replaced Java's `List<CodeUnitContainer>` with Python's built-in list type (`list`)
* Replaced Java's `getArity()` and `getMnemonic()` methods with dictionary accessors (`x['arity']` and `x['mnemonic']`, etc.)
* Removed the `@Override` annotations, since they are not necessary in Python
* Changed the method names to be more concise (e.g. `lengthOfX()` -> `length_of_x`)
* Replaced Java's `return xList.get(index - 1);` with dictionary accessors (`self.x_list[index - 1]`, etc.)