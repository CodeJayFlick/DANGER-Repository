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

class LldbModelTargetEventScope:
    def __init__(self):
        pass

    # The object can emit events affecting itself and its successors
    def extend(self, type: any) -> None:
        return

import lldb_model_target_object  # assuming this is a Python module with class LldbModelTargetObject
from target_event_scope import TargetEventScope  # assuming this is a Python module with class TargetEventScope

LldbModelTargetEventScope = type('LldbModelTargetEventScope', (LldbModelTargetObject, TargetEventScope), {})
```

Please note that the above code assumes you have `lldb_model_target_object` and `target_event_scope` modules available in your Python environment.