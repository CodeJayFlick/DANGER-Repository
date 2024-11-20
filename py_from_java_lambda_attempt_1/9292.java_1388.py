Here is the translation of the Java code to Python:
```
# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

class DockingActionProvider:
    """An interface for objects (really Components) to implement that signals they provide actions
       for the Docking environment.
    """

    @property
    def get_docking_actions(self):
        raise NotImplementedError("Must be implemented by subclass")

# Note: this API is not likely used by forward-acing clients and can be removed in the next release
class DockingActionProviderIf(DockingActionProvider):
    """@deprecated use Tool"""
    pass

if __name__ == "__main__":
    # Example usage:
    class MyDockingActionProvider(DockingActionProviderIf):
        def get_docking_actions(self):
            return ["action1", "action2"]

    my_provider = MyDockingActionProvider()
    print(my_provider.get_docking_actions())  # Output: ['action1', 'action2']
```
Note that I've kept the original Java-style comments and licensing information, but translated them to Python syntax. The `get_docking_actions` method is implemented as a property in Python, which allows it to be accessed like an attribute (`my_provider.get_docking_actions()`).