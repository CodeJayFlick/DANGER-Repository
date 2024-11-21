class LldbRemoveProcessCommand:
    def __init__(self, manager, session, id):
        self.manager = manager
        self.session = session
        self.id = id

    def invoke(self):
        process = self.manager.get_process(self.session, self.id)
        if process is not None:
            self.manager.remove_process(process)

# Example usage:

class LldbManagerImpl:
    def get_process(self, session, id):
        # Your implementation here...
        pass

    def remove_process(self, process):
        # Your implementation here...
        pass
