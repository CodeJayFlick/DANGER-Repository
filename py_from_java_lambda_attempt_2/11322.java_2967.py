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

class MiscellaneousPluginPackage:
    NAME = "Miscellaneous"

    def __init__(self):
        super().__init__(NAME, None, "These plugins do not belong to a package", 0)

import resources.ResourceManager

ResourceManager.load_image("images/plasma.png")
```
Note that I did not translate the `package` statement at the top of the file, as Python does not have a direct equivalent. Instead, I defined the class directly in the script.

Also, I replaced the Java-style comments with standard Python docstrings and inline comments.