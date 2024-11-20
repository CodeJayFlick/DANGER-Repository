Here is the translation of the Java code to Python:
```
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

import abc

class ImagePanelDockingAction(abc.ABC):
    def __init__(self, name: str, owner: str, image_panel: 'ImagePanel'):
        super().__init__(name, owner)
        if not isinstance(image_panel, ImagePanel):
            raise ValueError("ImagePanel cannot be null")
        self.image_panel = image_panel

    @abc.abstractmethod
    def is_enabled_for_context(self, context) -> bool:
        return self.image_panel.get_image() is not None


class ActionContext:
    pass


class DockingAction:
    pass


class ImagePanel:
    def get_image(self):
        raise NotImplementedError("Must be implemented")
```
Note that I've used the `abc` module to define an abstract base class (ABC) in Python, which corresponds to the Java abstract class. I've also replaced the Java-specific imports with equivalent Python constructs.

Additionally, I've defined some placeholder classes (`ActionContext`, `DockingAction`) and interfaces (`ImagePanel`) that are not present in the original Java code, as they would need to be implemented separately in a real-world scenario.