Here is the translation of the Java code to Python:

```
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

from abc import ABC, abstractmethod

class GadpClientTargetEnvironment(ABC):
    def __init__(self):
        pass
    
    @abstractmethod
    def nothing_to_add(self):
        pass
```

Note that Python does not have a direct equivalent to Java's `interface` keyword. Instead, we define an abstract base class (ABC) using the `abc` module, which provides support for abstract methods and classes in Python. The `nothing_to_add` method is declared as abstract because it has no implementation and must be implemented by any subclass that inherits from this ABC.