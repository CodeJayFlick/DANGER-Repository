Here is the translation of the Java code to Python:
```
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class InvalidNode:
    def __init__(self, value, comment, parent, line_num):
        super().__init__(value, comment, parent, line_num)
        self.config.errors += 1

# class SectionNode: # This is not defined in the original code
```
Note that I did not translate the `VoidNode` and `ConfigReader` classes as they were not provided in the original Java code. Also, I assumed that there was a `config` object with an `errors` attribute, but this could be replaced by any other mechanism to keep track of errors.

Also, please note that Python does not have direct equivalent of Java's package and import statements. The above code is just a translation of the provided Java class into Python.