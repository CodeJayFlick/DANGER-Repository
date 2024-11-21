class JdiModelTargetModule:
    def __init__(self, modules, module, is_element):
        super().__init__(modules, module, is_element)
        self.module = module

    @staticmethod
    def get_unique_id(module):
        if module.name() is None:
            return "#" + str(hash(module))
        else:
            return module.name()

    def change_attributes(self, display_attribute_name="Initialized"):
        pass  # This method seems to be incomplete in the original Java code.

    async def init(self) -> asyncio.Future[None]:
        return asyncio.create_future(None)

    def get_display(self):
        if self.module is None:
            return super().get_display()
        else:
            return JdiModelTargetModule.get_unique_id(self.module)
