# This file is licensed under the Apache License, Version 2.0 (the "License");
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

import abc

class AbstractFunctionGraphTransitionJob(metaclass=abc.ABCMeta):
    def __init__(self, controller: 'FGController', use_animation: bool = False) -> None:
        super().__init__()
        self.controller = controller

    @property
    def function_graph(self) -> 'FunctionGraph':
        return self.controller.get_function_graph_data().get_function_graph()

    @property
    def function_graph_layout(self) -> 'FGLayout':
        return self.function_graph.get_layout()
