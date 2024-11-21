Here is the translation of the Java code to Python:
```
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

class DbgAddSessionCommand:
    def __init__(self, manager):
        pass

    def complete(self, pending):
        return DbgSessionImpl(manager)

class AbstractDbgCommand(metaclass=abc.ABCMeta):
    @abstractmethod
    def complete(self, pending):
        pass

class DbgPendingCommand(ABC):
    @abstractmethod
    pass

class DbgManager:
    pass

class DbgSession:
    pass

class DbgManagerImpl(DbgManager):
    pass

class DbgSessionImpl(DbgSession):
    def __init__(self, manager):
        super().__init__()
```
Note that I've used Python's built-in `abc` module to implement abstract classes and methods. This is equivalent to Java's abstract classes and interfaces.

Also, in the original code, there are no specific implementation details provided for the `DbgManager`, `DbgSession`, etc. classes, so I've left those as simple placeholders (`pass`) in the Python translation.