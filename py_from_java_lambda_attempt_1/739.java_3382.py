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

class DbgModelTargetConfigurable:
    def __init__(self):
        pass

from .DbgModelTargetObject import *
from ghidra.dbg.target import TargetConfigurable

__all__ = ['DbgModelTargetConfigurable']
```

Please note that Python does not have direct equivalent of Java's interface concept. However, we can achieve similar functionality using abstract classes or protocols in Python. In this translation, I used a class to represent the `DbgModelTargetConfigurable` interface from the given Java code.