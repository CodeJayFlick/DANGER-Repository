Here is the translation of the Java code to Python:
```
# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

class HelpActionManager:
    """Register help for a specific component."""

    def set_help_location(self, comp: JComponent, help_location: 'HelpLocation') -> None:
        """
        Enable help for a component.
        
        :param comp: Component that has help associated with it
        :param help_location: Help content location
        """
        pass  # TO DO: implement this method

# Note: In Python, we don't have an equivalent to Java's "interface" concept. Instead,
# we can define a class with abstract methods (i.e., methods that are declared but not implemented).
```
Note that I've kept the `set_help_location` method as is, since it seems like a placeholder for some actual implementation. In Python, you would typically implement this method in a subclass of `HelpActionManager`.