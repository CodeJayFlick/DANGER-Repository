class DbgCommandRunningEvent:
    def __init__(self):
        pass  # equivalent to super() in Java

    def new_state(self) -> str:
        return "RUNNING"
