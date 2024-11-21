Here is the translation of the Java code to Python:
```
# Licensed under Apache License 2.0 (the "License");
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

class GhidraFileChooserPanelListener:
    def __init__(self):
        pass

    def file_changed(self, file: str) -> None:
        """Notification of a new file."""
        print(f"File changed to {file}")

    def file_dropped(self, file: str) -> None:
        """Notification that a new file was dropped on the panel."""
        print(f"New file dropped: {file}")
```
Note that I did not include any imports or package declarations as they are not necessary in Python. Also, I used type hints for the `file` parameter to indicate its expected type (string).