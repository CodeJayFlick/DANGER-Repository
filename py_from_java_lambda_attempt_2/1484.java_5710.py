Here is the translation of the Java code to Python:
```
# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import unittest

class InVmModelForGdbBreakpointsTest(unittest.TestCase):
    def test_model_host(self):
        self.assertEqual(InVmGdbModelHost().__str__(), "InVmGdbModelHost")

if __name__ == "__main__":
    unittest.main()
```
Note that I've removed the Java-specific annotations and imports, as well as the `@Override` decorator (which is not necessary in Python). The test method has been renamed to follow PEP 8 conventions.