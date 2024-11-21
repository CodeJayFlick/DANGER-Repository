Here is the translation of the given Java code into Python:

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

class ImageRoot_Lollipop:
    kResolutionMethod = 0
    kImtConflictMethod = 1
    kDefaultImt = 2
    kCalleeSaveMethod = 3
    kRefsOnlySaveMethod = 4
    kRefsAndArgsSaveMethod = 5
    kDexCaches = 'kDexCaches'
    kClassRoots = 'kClassRoots'
    kImageRootsMax = 'kImageRootsMax'

print(ImageRoot_Lollipop.__dict__)
```

This Python code defines a class `ImageRoot_Lollipop` with several attributes, each representing an enum value from the original Java code. The last line prints out the dictionary representation of this class, which contains all its attribute names and values.