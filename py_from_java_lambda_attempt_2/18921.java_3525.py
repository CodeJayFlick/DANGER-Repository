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
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections

class AuthenticationDisabledProfile:
    CONFIG_OVERRIDES = collections.defaultdict(str, {"nessie.server.authentication.enabled": "false"})

    def get_config_overrides(self):
        return dict(self.CONFIG_OVERRIDES)
```
Note that I've used Python's built-in `defaultdict` class from the `collections` module to create a dictionary with default values. This is equivalent to Java's `ImmutableMap.of()` method.

Also, in Python, we don't need an explicit `@Override` annotation for methods, as it's implied by the method signature matching exactly with the one in the parent class (in this case, the abstract base class `QuarkusTestProfile`).