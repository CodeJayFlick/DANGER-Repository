class Help:
    help_service = None

    def __init__(self):
        self.help_service = DefaultHelpService()

    @classmethod
    def get_help_service(cls):
        return cls.help_service

    @classmethod
    def install_help_service(cls, service):
        cls.help_service = service
        DockingWindowManager.set_help_service(service)
