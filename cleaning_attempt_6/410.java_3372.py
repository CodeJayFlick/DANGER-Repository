class DebugProcessId:
    def __init__(self, id):
        self.id = id

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, DebugProcessId):
            return False
        that = other
        return self.id == that.id

    def __lt__(self, other):
        return self.id < other.id

    def __str__(self):
        return f"<dbgeng.dll Engine PID {self.id}>"
