Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class NessieBackendThrottledException(Exception):
    def __init__(self, server_error: Exception) -> None:
        super().__init__(str(server_error))
```

Note that Python does not have a direct equivalent to Java's `extends` keyword. Instead, we define our custom exception class (`NessieBackendThrottledException`) as a subclass of the built-in `Exception` class in Python.