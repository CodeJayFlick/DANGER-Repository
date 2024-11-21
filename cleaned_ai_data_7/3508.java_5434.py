class CodeViewerActionContext:
    def __init__(self, provider):
        super().__init__(provider, provider)

    def __init__(self, provider, location):
        super().__init__(provider, provider, location)

    @property
    def is_dynamic_listing(self):
        return (getattr(get_component_provider(), 'is_dynamic_listing')).__call__()
