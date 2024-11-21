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

import ghidra

class CallAnotherScript:
    def run(self):
        self.run_script("HelloWorldScript.py")
        self.run_script("HelloWorldPopupScript.py")

if __name__ == "__main__":
    script = CallAnotherScript()
    try:
        script.run()
    except Exception as e:
        print(f"An error occurred: {e}")
```

Please note that Python does not support Java-like constructs such as `@Override`, and the equivalent code is written in a more straightforward manner.