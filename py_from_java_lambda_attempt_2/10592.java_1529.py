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

class XmlAttributeException(Exception):
    """A runtime exception that is thrown when invalid or missing attributes are encountered."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
```
Note that I've kept the same structure and naming conventions as the original Java code. In Python, we don't need to explicitly define a constructor (`__init__` method), but it's common practice to include one when creating custom exceptions like this.