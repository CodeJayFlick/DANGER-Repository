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

class ComponentCellEditorListener:
    NEXT = 1
    PREVIOUS = 2
    UP = 3
    DOWN = 4

    def move_cell_editor(self, direction: int, value: str):
        pass
```

Note that in Python, we don't need to declare the types of variables or methods. Also, there is no concept of interfaces like Java; instead, you can use abstract classes with all methods declared as `abstract` (which means they must be implemented by any subclass) or just leave them empty and unimplemented if it's not necessary for your code.