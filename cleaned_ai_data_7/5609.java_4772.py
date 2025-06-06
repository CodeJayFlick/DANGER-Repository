# Apache License 2.0
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from abc import ABC, abstractmethod

class CodeComparisonPanelActionContext(ABC):
    @abstractmethod
    def get_code_comparison_panel(self) -> 'CodeComparisonPanel[FieldPanelCoordinator]':
        pass


class FieldPanelCoordinator:
    pass


class CodeComparisonPanel(ABC):
    @abstractmethod
    def __init__(self, coordinator: type['FieldPanelCoordinator']):
        self.coordinator = coordinator

    def get_coordinator(self) -> type['FieldPanelCoordinator']:
        return self.coordinator
