class ComposedSleighUseropLibrary:
    def __init__(self, libraries):
        self.userops = {}
        for lib in libraries:
            for def_ in lib.get_userops().values():
                if self.userops.setdefault(def_.name, def_) is not None:
                    raise ValueError(f"Cannot compose libraries with conflicting definitions on {def_.name}")
        return

    @property
    def userops(self):
        return dict(self.__userops)

class SleighUseropDefinition:
    def __init__(self, name):
        self.name = name

class SleighUseropLibrary:
    def get_userops(self):
        # implement this method to return a dictionary of user ops
        pass
