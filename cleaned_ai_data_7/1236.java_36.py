class DelegateDbgModel2TargetObject:
    def __init__(self, model, parent, key, obj):
        self.model = model
        self.parent = parent
        self.key = key
        self.obj = obj
        self.state = ProxyState(model, obj)
        self.cleanable = CLEANER.register(self, state)

class ProxyState:
    def __init__(self, model, obj):
        self.model = model
        self.obj = obj

    def run(self):
        self.obj.dereference()

CLEANER = Cleaner.create()
LOOKUP = MethodHandles.lookup()

class DbgModelTargetObject:
    def __init__(self, parent, key, obj):
        super().__init__()
        self.parent = parent
        self.key = key
        self.obj = obj

    @property
    def proxy(self):
        return self.get_proxy()

    def get_proxy(self):
        return self.proxy

class DbgModelTargetContainer:
    pass

class DelegateDbgModel2TargetObject(DbgModelTargetObject, DbgModelTargetAccessConditioned,
                                     DbgModelTargetExecutionStateful, DbgModelTargetBptHelper):
    def __init__(self, model, parent, key, obj, mixins):
        super().__init__(parent, key, obj)
        self.access_listener = self.check_exited
        for mixin in mixins:
            if isinstance(mixin, type(self)):
                return

class DbgModelTargetAccessConditioned:
    pass

class DbgModelTargetExecutionStateful:
    pass

class DbgModelTargetBptHelper:
    pass

def check_exited(state, cause):
    # implementation of the method
    pass

def lookup_wrapper_type(type, parent_name):
    if type == "Available":
        return DbgModelTargetAvailableContainer
    elif type == "Sessions":
        return DbgModelTargetSessionContainer
    # ... and so on for all possible types
    else:
        return None

def make_proxy(model, parent, key, obj):
    mixins = []
    if isinstance(obj.get_kind(), ModelObjectKind.METHOD):
        mixins.append(DbgModelTargetMethod)
    elif mixin := lookup_wrapper_type(key, parent_name):
        mixins.append(mixin)

    return DelegateDbgModel2TargetObject(model, parent, key, obj, mixins).get_proxy()

def get_hint_for_object(obj):
    kind = obj.get_kind()
    if kind is None:
        return ""
    else:
        return str(kind.name())

@staticmethod
def do_invalidate(branch, reason):
    super().do_invalidate(branch, reason)
    model_manager.remove_state_listener(access_listener)

def on_running():
    invalidate()

def on_stopped():
    set_accessible(True)

def on_exit():
    set_accessible(True)

class DbgModelTargetRegisterContainer:
    pass

@staticmethod
def thread_changed_specific(state, reason):
    if state == DbgState.RUNNING:
        return
    # ... and so on for all possible states
