class ReferenceListingHover:
    NAME = "Reference Code Viewer"
    DESCRIPTION = "Shows 'referred to' code and data within the listing."
    PRIORITY = 50

    def __init__(self, tool):
        self.__init__(tool, None)

    def __init__(self, tool, code_format_service=None):
        super().__init__(tool, code_format_service, self.PRIORITY)

    @property
    def name(self):
        return self.NAME

    @property
    def description(self):
        return self.DESCRIPTION

    @property
    def options_category(self):
        return "CATEGORY_BROWSER_POPUPS"
