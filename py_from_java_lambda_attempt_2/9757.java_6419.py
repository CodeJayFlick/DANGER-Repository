Here is the translation of the Java code to Python:
```
# Copyright 2023 (your name)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import typing

class FloatColumnTypeMapper:
    def convert(self, value: float) -> float:
        # Use strings to avoid getting extra precision digits.
        return float(str(value))

if __name__ == "__main__":
    mapper = FloatColumnTypeMapper()
    print(mapper.convert(3.14))  # Output: 3.14
```
Note that I've kept the same class name and method signature as the original Java code, but with Python syntax. The `convert` method takes a float value, converts it to a string using the `str()` function, and then back to a float using the `float()` constructor.