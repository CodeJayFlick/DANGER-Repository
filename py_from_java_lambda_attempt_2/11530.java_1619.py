Here is the translation of the given Java code into Python:

```Python
# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class FamilySymbol:
    def __init__(self):
        pass

    def get_pattern_value(self):
        raise NotImplementedError("This method must be implemented by subclasses")

import abc

class TripleSymbol(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_pattern_value(self):
        pass
```

Note that Python does not have direct equivalent of Java's abstract classes and interfaces, but we can achieve similar functionality using the `ABC` (Abstract Base Class) module in Python.