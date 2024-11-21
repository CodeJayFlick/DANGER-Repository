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
