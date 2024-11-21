Here is the translation of the given Java-like code into pure Python:

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

class VarnodeType:
    Register = 0
    Stack = 1
    Memory = 2

print(VarnodeType.Register)  # prints: 0
print(VarnodeType.Stack)      # prints: 1
print(VarnodeType.Memory)     # prints: 2