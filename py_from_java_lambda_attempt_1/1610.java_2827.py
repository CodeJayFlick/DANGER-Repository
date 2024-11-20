Here is the translation of the Java code to Python:
```
# Licensed under the Apache License, Version 2.0 (the "License");
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

class LldbSessionCreatedEvent:
    def __init__(self, info):
        self.info = info

import lldb.debug_session_info as DebugSessionInfo

LldbSessionCreatedEvent.__bases__ = (object,)
```
Note that I've kept the license information at the top of the file, just like in the original Java code. In Python, we don't need to declare classes with `public` or use packages like `agent.lldb.manager.evt`, so those parts are omitted.

The main difference between the two languages is that Python uses indentation instead of curly braces `{}` to define blocks of code (e.g., methods). I've also removed the unnecessary imports and type declarations, as they're not needed in Python.