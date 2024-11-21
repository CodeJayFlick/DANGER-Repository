class ListingActionContext:
    def __init__(self, provider: object, navigatable: object):
        super().__init__(provider, navigatable)

    def __init__(self, provider: object, navigatable: object, location: object):
        super().__init__(provider, navigatable, location)

    def __init__(self, provider: object, navigatable: object, program: object, location: object, selection1: object, highlight: object):
        super().__init__(provider, navigatable, program, location, selection1, highlight)
