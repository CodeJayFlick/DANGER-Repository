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

from enum import Enum

class GhidraFileChooserMode(Enum):
    FILES_ONLY = 1
    DIRECTORIES_ONLY = 2
    FILES_AND_DIRECTORIES = 3

    def supports_files(self) -> bool:
        return self in [GhidraFileChooserMode.FILES_ONLY, GhidraFileChooserMode.FILES_AND_DIRECTORIES]

    def supports_directories(self) -> bool:
        return self in [GhidraFileChooserMode.DIRECTORIES_ONLY, GhidraFileChooserMode.FILES_AND_DIRECTORIES]
```
Note that I've used the `Enum` class from Python's built-in `enum` module to define an enumeration. The rest of the code is a direct translation of the Java code to Python.