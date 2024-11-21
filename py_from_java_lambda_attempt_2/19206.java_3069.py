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

class SerializableGetter(metaclass=type):
    def __init__(self, R=None, A=None):
        super().__init__()

    @property
    def is_deprecated(self) -> bool:
        return True

# This class is abstract and does not have any methods or properties.
```

Please note that Python doesn't support Java-like generics (type parameters), so I removed the `<R, A>` part. Also, there's no direct equivalent of Java's `@Deprecated` annotation in Python; instead, you can use a property to indicate whether an object is deprecated or not.