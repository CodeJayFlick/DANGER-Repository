Here is the translation of the Java code to Python:
```
# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class ChangeMembershipException(Exception):
    def __init__(self, err_msg: str) -> None:
        super().__init__(f"Change membership fails, error message={err_msg}")
```
Note that I've kept the same class name and method signature as the original Java code, but translated it to Python syntax. Specifically:

* The `package` statement is not needed in Python, so I removed it.
* The `public` keyword is not used in Python, since everything is public by default.
* The constructor (`__init__`) takes a single argument `err_msg`, which is passed to the superclass's constructor using the `super()` function.