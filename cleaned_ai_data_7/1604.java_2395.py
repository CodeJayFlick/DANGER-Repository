class LldbProcessExitedEvent:
    def __init__(self, exit_code):
        self.exit_code = exit_code

    @property
    def state(self):
        return "exited"

# This part doesn't have a direct equivalent in Python. It seems to be related to SWIG (a software wrapper generator) and its StateType enum.
