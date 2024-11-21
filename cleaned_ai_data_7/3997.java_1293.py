# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

import abc

class InterpreterPanelService:
    def __init__(self):
        pass

    @abc.abstractmethod
    def create_interpreter_panel(self, interpreter: 'InterpreterConnection', visible: bool) -> 'InterpreterConsole':
        """Creates a new interpreter panel.
        
        Args:
            interpreter (InterpreterConnection): A connection back to the interpreter.
            visible (bool): True if the panel should be visible when created; otherwise, false.

        Returns:
            InterpreterConsole: The interpreter console that corresponds to the panel.
        """
        pass

class ServiceInfo:
    def __init__(self):
        pass
