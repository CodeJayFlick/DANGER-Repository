Here is the translation of the Java code to Python:
```
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

class NessieServiceException(Exception):
    def __init__(self, error: 'NessieError') -> None:
        super().__init__(error.get_full_message())
        self.error = error

    @property
    def error(self) -> 'NessieError':
        return self._error

# Note: In Python, we don't need to define the NessieError class as it's not provided in the original Java code.
```
Note that I've kept the same structure and naming conventions as the original Java code. However, since Python is a dynamically-typed language, some changes were necessary:

* The `public` access modifier was removed, as Python does not have explicit access modifiers.
* The constructor (`__init__`) now takes an argument of type `'NessieError'`, which is a string in Python (equivalent to the Java class).
* I used the `@property` decorator to define a read-only property for the `error` attribute, equivalent to the getter method in Java.
* The rest of the code remains largely unchanged.