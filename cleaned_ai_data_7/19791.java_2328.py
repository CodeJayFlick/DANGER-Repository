class JavaFunction:
    def __init__(self):
        pass

    def set_signature(self, sign):
        super().__init__()
        
    def set_name_and_params(self, name: str, parameters: list, return_type: type, single: bool) -> None:
        self.set_signature(Signature(name, parameters, return_type, single))

    def execute(self, e: 'FunctionEvent', params: list) -> list:
        pass

class Signature:
    def __init__(self, name: str, parameters: list, return_type: type, single: bool):
        self.name = name
        self.parameters = parameters
        self.return_type = return_type
        self.single = single

class FunctionEvent:
    pass

def description(self, *description) -> 'JavaFunction':
    if not hasattr(self, 'description'):
        setattr(self, 'description', list(description))
    return self

def examples(self, *examples) -> 'JavaFunction':
    if not hasattr(self, 'examples'):
        setattr(self, 'examples', list(examples))
    return self

def since(self, since: str) -> 'JavaFunction':
    if not hasattr(self, 'since'):
        setattr(self, 'since', [since])
    return self

class ClassInfo:
    pass
