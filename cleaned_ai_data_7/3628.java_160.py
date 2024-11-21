import pyjnius

class PointerDataAction:
    def __init__(self, plugin):
        super().__init__(plugin)

POINTER_KEY_BINDING = "ctrl+p"

def get_default_key_stroke(self):
    return POINTER_KEY_BINDING
