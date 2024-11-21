class LldbSetActiveSessionCommand:
    def __init__(self, manager, session):
        self.manager = manager
        self.session = session

    def invoke(self):
        client = self.manager.get_client()
        debugger = client.get_debugger()
        debugger.set_selected_target(self.session)
