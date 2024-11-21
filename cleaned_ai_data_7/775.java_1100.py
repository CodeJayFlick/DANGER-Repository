class DbgModelTargetProcessContainer:
    def __init__(self):
        pass

    def get_target_process(self, id: 'DebugProcessId') -> 'DbgModelTargetProcess':
        # implement this method
        raise NotImplementedError("Method not implemented")

    def get_target_process(self, process: 'DbgProcess') -> 'DbgModelTargetProcess':
        # implement this method
        raise NotImplementedError("Method not implemented")
