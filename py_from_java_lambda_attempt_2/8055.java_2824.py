Here is the translation of the given Java code into equivalent Python:

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

class AbstractGlobalDataMsSymbol:
    """This class represents various flavors of Global Data symbol."""
    
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', internals):
        super().__init__(pdb, reader, internals)

if __name__ == "__main__":
    pass
```

Note that Python does not have direct equivalent to Java's abstract classes and interfaces. However, we can achieve similar functionality using inheritance and polymorphism in Python.

Also note that the `PdbException` class is missing from this translation as it was not provided with the original code.