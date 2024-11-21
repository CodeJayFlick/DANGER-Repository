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

class ImageMethod_Pie:
    kResolutionMethod = 0
    kImtConflictMethod = 1
    kImtUnimplementedMethod = 2
    kSaveAllCalleeSavesMethod = 3
    kSaveRefsOnlyMethod = 4
    kSaveRefsAndArgsMethod = 5
    kSaveEverythingMethod = 6
    kSaveEverythingMethodForClinit = 7
    kSaveEverythingMethodForSuspendCheck = 8

ImageMethodsCount = len(ImageMethod_Pie.__dict__)

print(ImageMethodsCount)
```

This Python code defines an enumeration `ImageMethod_Pie` with the same values as in the Java code. The last line calculates and prints the number of elements (or keys) in this dictionary, which is equivalent to the `kImageMethodsCount` field in the original Java code.