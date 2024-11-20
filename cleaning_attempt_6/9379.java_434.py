class DockingApplicationConfiguration:
    def __init__(self):
        self.show_splash_screen = True

    def is_headless(self):
        return False

    @property
    def error_display(self):
        from . import docking_error_display  # Assuming this module exists in the same package as your code
        return DockingErrorDisplay()

    def set_show_splash_screen(self, show_splash_screen: bool) -> None:
        self.show_splash_screen = show_splash_screen

    @property
    def is_show_splash_screen(self):
        return self.show_splash_screen

    def initialize_application(self) -> None:
        super().initialize_application()  # Assuming this method exists in the parent class, otherwise remove it

        from . import docking_windows_look_and_feel_utils
        docking_windows_look_and_feel_utils.load_from_preferences()

        if self.show_splash_screen:
            from . import splash_screen
            splash_screen.show_splash_screen()
        
        from . import application_key_manager_factory
        application_key_manager_factory.set_key_store_password_provider(
            PopupKeyStorePasswordProvider())  # Assuming this class exists in the same package as your code

