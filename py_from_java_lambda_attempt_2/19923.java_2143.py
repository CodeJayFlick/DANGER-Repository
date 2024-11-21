Here is the translation of the Java code to Python:

```
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Skript is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Skript. If not, see <http://www.gnu.org/licenses/>.

class EmptyStacktraceException(Exception):
    def __init__(self):
        super().__init__()
```

Note that Python does not require explicit declaration of variables or methods like Java does. Also, there is no direct equivalent to the `serialVersionUID` in Java, as it's a mechanism for versioning serialization formats and isn't directly applicable to Python.