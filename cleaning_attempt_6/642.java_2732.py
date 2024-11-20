class DbgRequestActivationCommand:
    def __init__(self, manager: 'DbgManagerImpl', activator: 'DbgModelTargetActiveScope', obj: 'TargetObject'):
        self.manager = manager
        self.activator = activator
        self.obj = obj

    def invoke(self):
        self.activator.do_request_activation(self.obj)
