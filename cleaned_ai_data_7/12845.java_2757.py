class ConditionalHelper:
    def __init__(self, inif: bool, sawelse: bool, handled: bool, copy: bool):
        self.inif = inif
        self.sawelse = sawelse
        self.handled = handled
        self.copy = copy

    @property
    def is_inif(self) -> bool:
        return self.inif

    @is_inif.setter
    def is_inif(self, value: bool):
        self.inif = value

    @property
    def sawelse(self) -> bool:
        return self.sawelse

    @sawelse.setter
    def sawelse(self, value: bool):
        self.sawelse = value

    @property
    def is_handled(self) -> bool:
        return self.handled

    @is_handled.setter
    def is_handled(self, value: bool):
        self.handled = value

    @property
    def copy(self) -> bool:
        return self.copy

    @copy.setter
    def copy(self, value: bool):
        self.copy = value

    def __str__(self):
        sb = f"{{"
        if self.inif:
            sb += "inif:"
        else:
            sb += "!inif:"
        if self.sawelse:
            sb += "sawelse:"
        else:
            sb += "!sawelse:"
        if self.handled:
            sb += "handled:"
        else:
            sb += "!handled:"
        if self.copy:
            sb += "copy"
        else:
            sb += "!copy"
        sb += "}}"
        return sb
