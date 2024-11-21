# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

from abc import ABC, abstractmethod

class LldbModelTargetSessionAttributes(ABC):
    def __init__(self):
        pass
    
    @abstractmethod
    def get_lldb_model_target_environment(self) -> 'LldbModelTargetEnvironment':
        pass
    
    @abstractmethod
    def set_lldb_events_listener_adapter(self, adapter: 'LldbEventsListenerAdapter'):
        pass

class LldbModelTargetEnvironment:
    # implement your logic here
    pass

class LldbEventsListenerAdapter:
    # implement your logic here
    pass
