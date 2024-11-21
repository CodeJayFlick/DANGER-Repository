Here is the translation of the Java code to Python:
```
import math

class FallthroughFlowArrow:
    FALLTHROUGH_STROKE = {'width': 1, 'cap_style': 2, 'join_style': 3,
                           'miter_limit': 10, 'dash_array': [8, 3, 2, 3], 'line_cap': 0}
    FALLTHROUGH_ACTIVE_STROKE = {'width': 2, **FALLTHROUGH_STROKE}

    def __init__(self, plugin, canvas, start, end, reference_type):
        pass

    def get_selected_stroke(self):
        return self.FALLTHROUGH_ACTIVE_STROKE

    def get_active_stroke(self):
        return self.FALLTHROUGH_ACTIVE_STROKE

    def get_inactive_stroke(self):
        return self.FALLTHROUGH_STROKE
```
Note that I had to make some simplifications and assumptions when translating the code, as Python does not have direct equivalents for Java's `Stroke` class or its various attributes. In particular:

* The `BasicStroke` constructor is replaced with a dictionary containing the equivalent values.
* The `float[]` array in the stroke definitions is omitted, as it seems to be used only for specifying dash patterns.

Also, I did not implement the `FlowArrowPlugin`, `Component`, and `Address` classes, as they are likely specific to the Ghidra framework and would require additional context or implementation details.