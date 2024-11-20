Here is the translation of the Java code to Python:
```
# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class ShowContinuousQueriesPlan:
    def __init__(self):
        super().__init__(ShowContentType.CONTINUOUS_QUERY)

if __name__ == "__main__":
    pass
```
Note that I've kept the same class name and method names as in the original Java code, but Python uses a different syntax. Specifically:

* The `package` statement is not needed in Python.
* The `public` access modifier is not used in Python (it's implicit).
* The constructor (`__init__`) has been renamed to follow Python convention.
* The `super()` call remains the same.

Also, I've added a simple `if __name__ == "__main__": pass` block at the end of the file, which is a common pattern in Python. This code does nothing when run as a script (i.e., not imported as a module), but it's there to indicate that this class can be used independently.