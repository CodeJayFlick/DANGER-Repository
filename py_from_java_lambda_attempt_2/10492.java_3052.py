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

class KeyedObject:
    """The KeyedObject class is used as a base class for objects which have keys. 
       Some specific examples of KeyedObject are Vertex and Edge."""
    
    def __init__(self):
        pass

    @property
    def key(self) -> int:
        """Returns the key for this KeyedObject."""
        return 0  # Replace with actual implementation if needed
```

Note that Python does not have direct equivalent of Java's interface concept. However, we can achieve similar functionality using abstract base classes (ABCs).