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

class CommentTypes:
    COMMENT_TYPES = [CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT, CodeUnit.EOL_COMMENT, CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT]

def get_types():
    return COMMENT_TYPES

if __name__ == "__main__":
    print(get_types())
```
Note that I did not include the `ghidra.program.model.listing.CodeUnit` import statement as it is specific to a Java-based environment and does not translate directly to Python. In Python, you would need to define your own equivalent class or data structure for representing code units.

Also, in Python, we do not have an explicit constructor (`__init__`) like in Java. The `CommentTypes` class can be instantiated without any issues.