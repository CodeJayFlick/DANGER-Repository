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
