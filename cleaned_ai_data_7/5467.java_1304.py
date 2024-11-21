class BrowserCodeUnitFormat:
    def __init__(self, service_provider):
        self.__init__(get_field_options(service_provider), True)

    def __init__(self, field_options, auto_update=False):
        super().__init__(BrowserCodeUnitFormatOptions(field_options, auto_update))

    @staticmethod
    def get_field_options(service_provider):
        options_service = service_provider.get(OptionsService)
        if not options_service:
            raise ValueError("Options service provider not found")
        return options_service.get(GhidraOptions.CATEGORY_BROWSER_FIELDS)

    def add_change_listener(self, listener):
        (self.options).addChangeListener(listener)

    def remove_change_listener(self, listener):
        (self.options).removeChangeListener(listener)


class BrowserCodeUnitFormatOptions:
    def __init__(self, field_options, auto_update=False):
        self.field_options = field_options
        self.auto_update = auto_update

    @property
    def options(self):
        return self.field_options


class OptionsService:
    pass


class GhidraOptions:
    CATEGORY_BROWSER_FIELDS = "CATEGORY_BROWSER_FIELDS"


if __name__ == "__main__":
    service_provider = ServiceProvider()
    browser_code_unit_format = BrowserCodeUnitFormat(service_provider)
