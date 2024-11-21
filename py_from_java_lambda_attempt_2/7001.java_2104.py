Here is the equivalent Python code:

```Python
# Licensed under the Apache License, Version 2.0 (the "License");
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

import importlib

class FileFormatAnalyzerFactory:
    @classmethod
    def get_analyzers(cls):
        return [cls() for cls in importlib.import_module('ghidra.file.analyzers').__dict__.values()
                if isinstance(cls, type) and issubclass(cls, object)]

# Usage example:
analyzers = FileFormatAnalyzerFactory.get_analyzers()
for analyzer in analyzers:
    print(analyzer.__name__)
```

Please note that Python does not have a direct equivalent to Java's `ClassSearcher` class. The above code uses the `importlib` module and dynamic import of modules to achieve similar functionality.