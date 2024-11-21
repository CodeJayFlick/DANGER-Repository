class LldbRequestActivationCommand:
    def __init__(self, manager, activator, obj):
        self.manager = manager
        self.activator = activator
        self.obj = obj

    def invoke(self):
        self.activator.do_request_activation(self.obj)
