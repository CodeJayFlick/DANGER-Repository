class MDReusableName:
    def __init__(self):
        self.fragment = None
        self.template_name = None

    def get_name(self):
        if self.fragment is not None:
            return self.fragment.get_name()
        elif self.template_name is not None:
            return self.template_name.get_name()
        else:
            return ""

    def set_name(self, name):
        if self.fragment is not None:
            self.fragment.set_name(name)
        # DO NOT DELETE THE FOLLOWING FRAGMENT--part of future work
#         elif self.qualified_name is not None:  #TODO: do we need this 20140520
#             self.qualified_name.set_name(name)
        else:
            if self.template_name is not None:
                self.template_name.set_name(name)

    def insert(self, builder):
        if self.fragment is not None:
            self.fragment.insert(builder)
        else:
            self.template_name.insert(builder)


class MDFragmentName:
    def __init__(self):
        pass

    def get_name(self):
        return ""

    def set_name(self, name):
        pass


class MDTemplateNameAndArguments:
    def __init__(self):
        pass

    def parse(self):
        pass
