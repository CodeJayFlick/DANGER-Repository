class DbgRequestFocusCommand:
    def __init__(self, manager: 'DbgManagerImpl', scope: 'DbgModelTargetFocusScope', obj: 'TargetObject'):
        self.manager = manager
        self.scope = scope
        self.obj = obj

    def invoke(self):
        self.scope.do_request_focus(self.obj)
