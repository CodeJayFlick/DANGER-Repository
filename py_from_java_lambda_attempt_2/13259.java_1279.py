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

class SyntheticAttribute:
    def __init__(self):
        pass

    def to_data_type(self) -> dict:
        return {"Synthetic_attribute": {}}

if __name__ == "__main__":
    synthetic_attr = SyntheticAttribute()
    print(synthetic_attr.to_data_type())
```
Note that I've removed the Java-specific constructs (e.g. `package`, `import`, etc.) and replaced them with Python's equivalent syntax. The code is now a simple Python class with an initializer method (`__init__`) and another method called `to_data_type`.