Here is the translation of the Java code to Python:
```
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

class ExamplesPluginPackage:
    NAME = "Examples"

    def __init__(self):
        super().__init__(NAME, ResourceManager.load_image("images/akregator.png"),
                         "These plugins are just examples of how to write a plugin.", EXAMPLES_PRIORITY)

import ghidra.framework.plugintool.util.PluginPackage
from resources import ResourceManager

EXAMPLES_PRIORITY = 0  # assume this is defined elsewhere in the code
```
Note that I've kept the same variable names and structure as the original Java code, but translated it to Python syntax.