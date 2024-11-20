class DbgBreakpointModifiedEvent:
    def __init__(self, info=None):
        self.bpt_id = None
        if info:
            super().__init__(info)
            self.bpt_id = info.get_number()
        else:
            super().__init__(None)

    @property
    def breakpoint_info(self):
        return self.info

    @property
    def id(self):
        return self.bpt_id


class DbgBreakpointInfo:  # Assuming this class exists in the original code, if not you can create it as well.
    pass
