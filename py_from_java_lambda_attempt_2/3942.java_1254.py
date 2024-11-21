Here is the translation of the given Java code into equivalent Python:

```Python
import xml.etree.ElementTree as ET

class DefaultNavigatableLocationMemento:
    def __init__(self, program, location):
        self.program = program
        self.location = location
        self.mementos = {}
        self.focused_navigatable = None

    def set_mementos(self):
        for navigatable in list(self.mementos.keys()):
            if not navigatable.is_visible():
                continue
            memento = self.mementos[navigatable]
            navigatable.set_memento(memento)

class SaveState:
    def __init__(self, element=None):
        self.element = element

    def put_int(self, key, value):
        root = ET.Element('root')
        int_element = ET.SubElement(root, 'int', attrib={key: str(value)})
        self.element = ET.tostring(root)

    def get_int(self, key):
        return int(ET.fromstring(self.element).find('.//' + key).attrib['value'])

class DefaultNavigatableLocationMemento(SaveState):
    def __init__(self, save_state=None, programs=None):
        super().__init__()
        if save_state is not None:
            self.focused_navigatable = NavigatableRegistry.get_navigatable(save_state.get_long('FOCUSED_NAV', 0))
            count = save_state.get_int('NUM_MEMENTOS', 0)
            for i in range(count):
                element = ET.fromstring(save_state.element).find('.//MEMENTO' + str(i)).attrib['value']
                nav_state = SaveState(element=element)
                nav_id = nav_state.get_long('NAV_ID', 0)
                navigatable = NavigatableRegistry.get_navigatable(nav_id)
                memento = LocationMemento.get_location_memento(nav_state, programs)
                if navigatable is not None and memento is not None:
                    self.mementos[navigatable] = memento

    def get_focused_navigatable(self):
        return self.focused_navigatable
```

Please note that this translation assumes the existence of classes `NavigatableRegistry`, `LocationMemento` and their respective methods, which are not provided in your code.