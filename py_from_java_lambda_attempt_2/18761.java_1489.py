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

class NoneAuthenticationProvider:
    AUTH_TYPE_VALUE = "NONE"

    @classmethod
    def get_instance(cls):
        return NoneAuthenticationProvider()

    def get_auth_type_value(self) -> str:
        return self.AUTH_TYPE_VALUE

    def build(self, config_supplier: callable) -> None:
        return None
```
Note that I've kept the same variable names and structure as the original Java code. In Python, we don't need to declare types for variables or method parameters (although it's good practice to include type hints like `-> str`), so some of the syntax is slightly different from Java.