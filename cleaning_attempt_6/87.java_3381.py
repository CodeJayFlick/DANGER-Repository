class DebuggerOpenProgramActionContext:
    def __init__(self, df):
        self.df = df
        self.hash_code = hash((type(self), df))

    @property
    def domain_file(self):
        return self.df

    def __hash__(self):
        return self.hash_code

    def __eq__(self, obj):
        if self is obj:
            return True
        elif not isinstance(obj, DebuggerOpenProgramActionContext):
            return False
        else:
            that = obj
            if not self.df == that.df:
                return False
            return True
