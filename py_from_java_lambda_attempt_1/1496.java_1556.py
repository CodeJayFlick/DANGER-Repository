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

class InVmModelForGdbSessionLauncherTest(unittest.TestCase):
    def test_model_host(self):
        return InVmGdbModelHost()

if __name__ == '__main__':
    unittest.main()
```
Note that I did not include any JUnit-specific annotations or imports, as Python's `unittest` module does not have direct equivalents. The code is simply a translation of the Java class into equivalent Python syntax.

Also, please note that this code assumes you are using Python 3.x and above. If you're using an earlier version (e.g., Python 2.x), some changes may be necessary to make it compatible with your environment.