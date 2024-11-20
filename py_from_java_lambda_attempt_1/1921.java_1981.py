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

import unittest

class InVmModelForLldbFactoryTest(unittest.TestCase):
    def test_model_host(self):
        from . import InVmLldbModelHost  # assuming this is in a separate file
        self.assertEqual(InVmLldbModelHost().__class__, type("InVmLldbModelHost"))

if __name__ == "__main__":
    unittest.main()
```
Note that I've removed the Java-specific syntax and replaced it with Python's equivalent. In particular:

* The `package` declaration is not needed in Python.
* The `import` statements are similar, but use Python's syntax instead of Java's.
* The class definition uses Python's syntax (`class`) instead of Java's (`public class`).
* The method signature uses Python's syntax (e.g., `def test_model_host(self)`) instead of Java's.
* I've assumed that the `InVmLldbModelHost` class is defined in a separate file, and imported it using the `. import` statement. If this is not the case, you'll need to modify the code accordingly.

Also note that Python does not have an exact equivalent to Java's `@Override` annotation; instead, we rely on the fact that the method signature matches exactly with the one in the parent class (`unittest.TestCase`).