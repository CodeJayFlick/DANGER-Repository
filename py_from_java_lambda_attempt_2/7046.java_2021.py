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

class ImageRoot_Nougat:
    """See https://android.googlesource.com/platform/art/+/nougat-release/runtime/image.h"""
    
    kDexCaches = 'kDexCaches'
    kClassRoots = 'kClassRoots'
    kImageRootsMax = 'kImageRootsMax'

# No equivalent of Java's enum in Python. The above class is used to emulate the functionality.
```

Please note that there isn't a direct translation for `enum` in Python, as it doesn't have an exact equivalent. In this case, I've created a simple class with static variables (`kDexCaches`, `kClassRoots`, and `kImageRootsMax`) to emulate the functionality of Java's enum.