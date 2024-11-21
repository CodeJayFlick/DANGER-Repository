from abc import ABCMeta, abstractmethod

class ActionContext:
    def __init__(self):
        pass

class DebuggerModelActionContext(ActionContext):
    def __init__(self, provider, path, tree):
        super().__init__()
        self.path = path

    def get_if(self, cls, getter):
        if not self.path:
            return None
        last = self.path[-1]
        if not issubclass(type(last), cls):
            return None
        node = type(last)(last)
        return getter(node)

class DebuggerModelService:
    pass

class DebuggerObjectModel:
    pass


# usage example:

def main():
    provider = "your_provider"
    path = ["node1", "node2"]
    tree = "your_tree"

    action_context = DebuggerModelActionContext(provider, path, tree)
    
    model_service = action_context.get_if(DebuggerModelService.__class__, lambda x: None)  # replace with actual getter
    debugger_model = action_context.get_if(DebuggerObjectModel.__class__, lambda x: None)  # replace with actual getter

if __name__ == "__main__":
    main()
