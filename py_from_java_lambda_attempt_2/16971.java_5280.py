Here is the translation of the Java code to Python:
```
# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

from typing import Iterator, List

class IMergePathSelector(Iterator[List['PartialPath']]):
    """IMergePathSelector select paths to be merged at a time if all paths of a device cannot be merged 
       at the same time."""
    pass
```
Note that I've used Python's type hints (`List` and `Iterator`) to indicate the types of the methods, but these are not enforced by Python itself. Additionally, since there is no equivalent concept in Python for Java's interfaces (which are abstract classes with only method declarations), we simply define a class with the same name as the interface.

Here's an explanation of the translation:

* The license information at the top remains unchanged.
* We import `Iterator` and `List` from the built-in `typing` module, which provides type hints for Python code.
* We define a class `IMergePathSelector` that inherits from `Iterator[List[PartialPath]]`. This is equivalent to Java's interface declaration. The `pass` statement indicates that this class has no implementation (i.e., it's an abstract class).
* I've kept the docstring (`"""..."""`) intact, as it provides a brief description of what the IMergePathSelector does.

Please note that Python doesn't have direct equivalent to Java interfaces or classes.