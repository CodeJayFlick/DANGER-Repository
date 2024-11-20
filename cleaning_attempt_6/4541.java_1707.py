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

class FieldMouseHandlerService:
    def add_field_mouse_handler(self, handler):
        pass  # implementation left out

import ghidra_app_util_viewer_field_FieldMouseHandler as FieldMouseHandler

FieldMouseHandlerService = type('FieldMouseHandlerService', (), {'add_field_mouse_handler': lambda self, handler: None})
