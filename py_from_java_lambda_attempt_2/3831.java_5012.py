Here is the translation of the given Java code into equivalent Python:

```Python
import tkinter as tk

class ConditionalFlowArrow:
    def __init__(self, plugin, canvas, start, end, reference_type):
        super().__init__()

    @staticmethod
    def get_selected_stroke():
        return NORMAL_ACTIVE_STROKE

    @staticmethod
    def get_active_stroke():
        return NORMAL_ACTIVE_STROKE

    @staticmethod
    def get_inactive_stroke():
        return CONDITIONAL_STROKE


# Initialize the strokes
CONDITIONAL_STROKE = tkStroke(1, 5.0)
NORMAL_ACTIVE_STROKE = tkStroke(2, 10.0)

class FlowArrow:
    pass

class RefType:
    pass

class Address:
    pass

class Component:
    pass

class FlowArrowPlugin:
    pass

# Usage
plugin = FlowArrowPlugin()
canvas = Component()
start_address = Address()
end_address = Address()
reference_type = RefType()

conditional_flow_arrow = ConditionalFlowArrow(plugin, canvas, start_address, end_address, reference_type)
```

Please note that Python does not have direct equivalents for Java classes like `Address`, `RefType`, and the graphical components. I've used placeholder names to represent these concepts in Python.

Also, there is no direct equivalent of Java's `BasicStroke` class in Python. The above code uses a simple representation of strokes using arbitrary values (1 and 2) as an example.