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

class SelectionGenerator:
    def add_selections(self, layout_index: int, translator: callable, selections: list):
        pass

if __name__ == "__main__":
    # Example usage
    selection_generator = SelectionGenerator()
    layout_index = 0x12345678
    translator = lambda x: f"Translated {x}"
    selections = [{"color": "red", "field_name": "Field1"}, {"color": "blue", "field_name": "Field2"}]
    selection_generator.add_selections(layout_index, translator, selections)
```
Note that I've used Python's type hints to indicate the expected types of the method parameters. In particular:

* `layoutIndex` is an integer (`int`)
* `translator` is a callable (i.e., a function or lambda expression) that takes one argument
* `selections` is a list of dictionaries, where each dictionary has two keys: `"color"` and `"field_name"`

I've also added some example usage at the end to demonstrate how you might use this class.