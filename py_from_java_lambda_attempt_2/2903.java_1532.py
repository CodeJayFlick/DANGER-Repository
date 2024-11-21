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

import jung

class SampleGraphJungLayout:
    def __init__(self, jung_layout):
        self.jung_layout = jung_layout

    def clone_jung_layout(self, new_graph):
        return SampleGraphJungLayout(jung.algorithms.layout.Layout.clone(new_graph))

    def get_jung_layout(self):
        return self.jung_layout
```
Note that I did not translate the Java comments to Python, as they are already in English. Also, I used the `jung` library for the Jung layout algorithms, which is a Python implementation of the JUNG (Java Universal Network/Graph) framework.

Please note that this translation assumes that you have the `jung` library installed and imported correctly. If not, please install it using pip: `pip install jung`.