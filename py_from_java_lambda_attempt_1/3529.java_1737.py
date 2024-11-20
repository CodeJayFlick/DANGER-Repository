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

class OtherPanelContext:
    def __init__(self, provider: object, program: object) -> None:
        super().__init__(provider, program)

import ghidra  # assuming this is a Python package or module

ghidra.app.context.ProgramActionContext = type('ProgramActionContext', (), {'__module__': 'ghidra'})
```
Note that I've used the `super()` function to call the parent class's constructor (`__init__` method), and also imported the `ghidra` package or module, assuming it exists in your Python environment.