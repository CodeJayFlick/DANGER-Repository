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

class ImageRootOreo:
    """https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/image.h"""
    
    kDexCaches = 'kDexCaches'
    kClassRoots = 'kClassRoots'
    kClassLoader = 'kClassLoader'  # App image only.
    kImageRootsMax = 'kImageRootsMax'

print(ImageRootOreo.__dict__)
```

Please note that Python does not have direct equivalent of Java's enum. The above code uses a class with constant variables to achieve similar functionality.