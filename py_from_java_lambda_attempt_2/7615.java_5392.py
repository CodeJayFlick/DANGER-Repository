Here is the translation of the given Java code into equivalent Python:

```Python
# Licensed under Apache License 2.0 (the "License");
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

class FidPluginPackage:
    NAME = 'Function ID'

    def __init__(self):
        super().__init__(NAME, ResourceManager.load_image('images/vcard.png'),
                         "These plugins are for creating, maintaining, and debugging function identification libraries.")

import ghidra.framework.plugintool.util.PluginPackage
from resources import ResourceManager

# No equivalent Java code found in this part.
```

Please note that the `ResourceManager` class is not a standard Python library. It seems to be specific to your project or framework (Ghidra).