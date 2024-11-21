class LldbRequestFocusCommand:
    def __init__(self, manager, scope, obj):
        self.manager = manager
        self.scope = scope
        self.obj = obj

    def invoke(self):
        self.scope.do_request_focus(self.obj)
