class JdiModelTargetLocalVariable:
    IS_ARGUMENT_ATTRIBUTE_NAME = "IsArg"
    VISIBLE_TYPE_ATTRIBUTE_NAME = "Type"

    def __init__(self, variables, var, is_element):
        super().__init__(variables, var.name(), var, is_element)
        self.var = var

        attributes = {
            JdiModelTargetLocalVariable.DISPLAY_ATTRIBUTE_NAME: var.name(),
            JdiModelTargetLocalVariable.VISIBLE_TYPE_ATTRIBUTE_NAME: var.type_name()
        }
        change_attributes(attributes)

    def populate_attributes(self):
        added_attributes = {"Attributes": {}}
        if self.var.is_argument():
            added_attributes["Attributes"]["isArgument"] = True
        return added_attributes

    async def request_attributes(self, refresh=False):
        await self.populate_attributes()

        attributes = {
            "Signature": self.var.signature(),
            "Type": None,
            "Generic Signature": None
        }
        if isinstance(self.var.type(), JdiModelTargetType):
            attributes["Type"] = self.var.type()
        try:
            type_ = await getInstance(var.type())
            attributes["Type"] = type_
        except ClassNotLoadedException:
            pass

        return CompletableFuture.completedFuture(None)

    async def init(self):
        return CompletableFuture.completedFuture(None)

    def get_display(self):
        if not hasattr(self, "var") or self.var is None:
            return super().get_display()
        else:
            return self.var.name()

class JdiModelTargetAttributesContainer:
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name

    async def add_attributes(self, attributes):
        pass

def change_attributes(attributes=None):
    # This method is not implemented in Python
    pass

async def getInstance(type_):
    # This method is not implemented in Python
    pass

class CompletableFuture:
    @staticmethod
    def completedFuture(result):
        return result
