class SetFunctionNameCmd:
    def __init__(self, entry, name, source):
        self.entry = entry
        self.name = name
        self.source = source
        self.msg = None

    def apply_to(self, obj):
        program = Program(obj)
        
        if not self.name or len(self.name) <= 0:
            self.name = None
        
        f = program.get_listing().get_function_at(self.entry)
        if f is None:
            return True
        
        try:
            f.set_name(self.name, self.source)
        except Exception as e:
            self.msg = str(e)
            return False
        
        return True

    def get_name(self):
        return "Rename Function"

    def get_status_msg(self):
        return self.msg
