Here is the translation of the Java code to Python:

```
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

class KeyEntryListener:
    def process_entry(self, key_stroke):
        pass

```

Note that Python does not have a direct equivalent to Java's `interface` keyword. Instead, we define a class with methods that must be implemented by any subclass or instance of this class. In this case, the `KeyEntryListener` class has one method, `process_entry`, which takes a single argument and returns no value (i.e., it is a "void" function).