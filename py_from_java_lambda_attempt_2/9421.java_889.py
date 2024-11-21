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

class MenuGroupListener:
    def menu_group_changed(self, menu_path: list[str], group: str) -> None:
        pass  # implement this method in your subclass

if __name__ == "__main__":
    pass
```
Note that I've kept the original license information at the top of the file. In Python, we don't have a direct equivalent to Java's `interface` keyword, so instead, I defined a class with a single abstract method (`menu_group_changed`). This allows you to create subclasses that implement this method.

Also, in Python 3.x, the type hinting is used for documentation purposes only and does not affect the runtime behavior of your code.