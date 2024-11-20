Here is the translation of the Java code to Python:
```
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

class GadpModelForGdbScenarioForkExitTest:
    def model_host(self):
        return GadpGdbModelHost()

import abc

class AbstractModelForGdbScenarioForkExitTest(abc.ABC):
    @abc.abstractmethod
    def model_host(self) -> object:
        pass

class GadpGdbModelHost:
    pass
```
Note that I've kept the same class and method names as in the original Java code, but Python is a dynamically-typed language, so some of the type annotations (e.g., `throws Throwable`) are not necessary. Additionally, Python does not have an equivalent to Java's `@Override` annotation, which indicates that a method overrides a method from its superclass.