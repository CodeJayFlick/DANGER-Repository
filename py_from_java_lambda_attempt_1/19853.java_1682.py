Here is the translation of the given Java code into Python:

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

__author__ = "Peter Güttinger"

class Verbosity:
    LOW = 0
    NORMAL = 1
    HIGH = 2
    VERY_HIGH = 3
    DEBUG = 4

print(Verbosity.LOW)
```

Please note that Python does not have an exact equivalent to Java's enum. The above code uses a class with constant variables instead, which serves the same purpose as an enum in Java.