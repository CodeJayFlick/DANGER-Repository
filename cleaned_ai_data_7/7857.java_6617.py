class MDPinPointerProperty:
    def __init__(self, dmang):
        super().__init__(dmang)

    #def __init__(self, modifierTypeName, dmang) -> None:
    #    super().__init__(modifierTypeName, dmang)
    #
    #def parseCVMod(self, dmang: MDMang) -> None:
    #    pass
    #
    #def emitCVMod(self, builder: StringBuilder) -> None:
    #    pass

    def emit(self, builder):
        if not self.modifierTypeName == "":
            builder.insert(0, "cli::pin_ptr<")
            builder.append(">")
        super().emit(builder)
        return builder.toString()
