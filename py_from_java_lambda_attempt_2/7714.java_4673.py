Here is the translation of the Java code into Python:

```Python
from collections import defaultdict, OrderedDict
import random

class AttributeFilters:
    def __init__(self):
        self.buttons = []
        self.multiset = defaultdict(int)
        self.selected_texts = set()
        self.listener_list = []

    @classmethod
    def builder(cls):
        return cls.Builder()

    class Builder:
        def __init__(self):
            self.excluded_attributes = set()
            self.elements = set()
            self.max_factor = 0.01
            self.button_supplier = lambda: None
            self.paint_function = lambda x: (255, 255, 255)

        @property
        def excluded(self):
            return self

        @excluded.setter
        def excluded(self, value):
            self.excluded_attributes = set(value)
            return self

        @property
        def elements(self):
            return self

        @elements.setter
        def elements(self, value):
            self.elements = set(value)
            return self

        @property
        def max_factor(self):
            return self.max_factor

        @max_factor.setter
        def max_factor(self, value):
            if not isinstance(value, (int, float)):
                raise TypeError("Max factor must be a number")
            self.max_factor = value
            return self

        @property
        def button_supplier(self):
            return self.button_supplier

        @button_supplier.setter
        def button_supplier(self, value):
            if callable(value) and not isinstance(value(), AbstractButton):
                raise TypeError("Button supplier must be a function that returns an AbstractButton")
            self.button_supplier = lambda: value()
            return self

        @property
        def paint_function(self):
            return self.paint_function

        @paint_function.setter
        def paint_function(self, value):
            if callable(value) and not isinstance(next(iter(map(lambda x: (x,), map(lambda y: y(), value())))), tuple)[0] in range(256):
                raise TypeError("Paint function must be a function that returns an RGB color")
            self.paint_function = lambda x: next(iter(map(lambda y: y(), value(x))))
            return self

        def build(self):
            return AttributeFilters(self)

    def __init__(self, builder):
        for element in builder.elements:
            attribute_map = {k: v for k, v in zip(element.get_attributes().keys(), element.get_attributes().values())}
            for key, value in attribute_map.items():
                if not builder.excluded_attributes.__contains__(key):
                    self.multiset[value] += 1
        threshold = max(2, len(builder.elements) * builder.max_factor)
        self.multiset = {k: v for k, v in self.multiset.items() if v >= threshold}
        for key in self.multiset:
            button = next(iter(map(lambda x: x(), builder.button_supplier())))
            button.set_foreground(self.paint_function(key))
            button.set_text(str(key))
            button.add_item_listener(lambda item: 
                (lambda event_type, selected_texts=self.selected_texts: 
                    if event_type == 'selected':
                        self.selected_texts.update({button.get_text()})
                        fire_item_state_changed(event_type)
                    elif event_type == 'deselected':
                        self.selected_texts.discard(button.get_text())
                        fire_item_state_changed(event_type))
                )(item, button.get_text()))
            self.buttons.append(button)

    def get_buttons(self):
        return self.buttons

def fire_item_state_changed(event_type):
    for listener in AttributeFilters.listener_list:
        if isinstance(listener, ItemListener):
            listener.itemStateChanged(ItemEvent(event_type))

class AbstractButton:
    pass
```

Please note that this translation is not perfect and some parts of the code might be missing or incorrect. The original Java code seems to have a lot of complexity which makes it difficult to translate into Python directly.