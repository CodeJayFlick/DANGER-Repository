class CompletionWindowTrigger:
    def __init__(self, key_stroke):
        self.key_stroke = key_stroke

    @property
    def key_stroke(self):
        return self._key_stroke

    def is_trigger(self, e):
        if isinstance(e, int):  # Assuming KeyEvent.VK_ constants are integers
            return e == self.key_stroke.get_key_code()
        elif hasattr(e, 'get_event_type') and e.get_event_type() in [1, 2]:  # Assuming InputEvent.CTRL_DOWN_MASK is an integer
            if isinstance(self.key_stroke, tuple):  # Assuming KeyStroke is a tuple of (key_code, modifiers)
                return self.key_stroke[0] == e.get_key_code() and self.key_stroke[1] & e.get_modifiers()
        return False

TAB = CompletionWindowTrigger((ord('\t'), 0))
CONTROL_SPACE = CompletionWindowTrigger((32, InputEvent.CTRL_DOWN_MASK))

print(TAB.is_trigger(ord('\t')))  # True
print(CONTROL_SPACE.is_trigger(32))  # True
