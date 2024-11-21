class Trigger:
    def __init__(self, script=None, name="", event=None, items=None):
        self.script = script
        self.name = name
        self.event = event
        self.debug_label = "unknown trigger"
        super().__init__(items)

    def execute(self, e):
        success = self.walk(e)
        Variables.remove_locals(e)
        return success

    def walk(self, e, debug=False):
        # implement this method as per your requirement
        pass

    def __str__(self, e=None, debug=False):
        if not debug:
            return f"{self.name} ({self.event})"
        else:
            return f"{self.name} ({self.event}) - {e}"

    @property
    def name(self):
        return self._name

    @property
    def event(self):
        return self._event

    @property
    def script(self):
        return self._script

    def set_line_number(self, line=-1):
        self.line = line

    @property
    def line_number(self):
        return self.line

    def set_debug_label(self, label):
        self.debug_label = label

    @property
    def debug_label(self):
        return self.debug_label


class Variables:
    @staticmethod
    def remove_locals(e):
        # implement this method as per your requirement
        pass
