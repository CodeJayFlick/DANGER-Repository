Here is the translation of the given Java code into Python:

```Python
# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

import ghidra

class PEF_script:
    def run(self):
        command = ghidra.app.commands.PefBinaryAnalysisCommand()
        command.apply_to(current_program=ghidra.current_program(), monitor=None)

# Run the script
script = PEF_script()
script.run()

```

Please note that this translation is not perfect, as Python and Java are different languages with their own syntax. The above code may need some adjustments to work correctly in a Python environment.