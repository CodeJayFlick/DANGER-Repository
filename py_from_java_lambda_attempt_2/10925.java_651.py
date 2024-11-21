Here is the equivalent Python code:

```Python
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

import unittest

class VisualGraphTestSuite(unittest.TestLoader):
    suites = [
        'GraphViewerTransformationsTest',
        'VisualGraphPathHighlighterTest',
        'VisualGraphViewUpdaterTest',
        'GraphViewerTest',
        'GraphComponentTest',
        'GridLocationMapTest',
        'VisualGraphViewTest',
        'FilteredVisualGraphTest',
        'VisualGraphJobRunnerTest',  # this is headless; run last to avoid environment conflicts
    ]

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's JUnit. However, the above code demonstrates how you can create a test suite in Python using its built-in `unittest` module.