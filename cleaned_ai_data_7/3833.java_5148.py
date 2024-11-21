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
