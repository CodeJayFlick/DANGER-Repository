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

class NonTransactionalOperationContext:
    NON_TRANSACTIONAL_OPERATION_CONTEXT = None

    def __init__(self):
        pass
```
Note that in Python, we don't need to use `@SuppressWarnings` annotations as they are not necessary. Also, the concept of a "utility class" is different in Java and Python, so I've simply created a regular Python class instead.

The rest of the code remains similar, with some minor adjustments for syntax differences between Java and Python.