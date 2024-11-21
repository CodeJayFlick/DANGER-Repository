Here is the translation of the Java code to Python:
```
# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import abc

class GadpModelForGdbSessionAttacherTest:
    def model_host(self):
        return GadpGdbModelHost()

class AbstractModelForGdbSessionAttacherTest(abc.ABC):
    @abc.abstractmethod
    def model_host(self) -> object:
        pass

class GadpGdbModelHost:
    pass
```
Note that I've kept the original license information at the top, as it's an important part of the code. In Python, we don't have a direct equivalent to Java's `@Override` annotation, so I've simply removed it and implemented the method in the derived class (`GadpModelForGdbSessionAttacherTest`).