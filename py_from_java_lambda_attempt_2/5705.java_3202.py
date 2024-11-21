Here is a translation of the Java code into equivalent Python code:

```Python
import platform
from tkinter import Tk as Taskbar  # For macOS taskbar support
from tkinter.messagebox import showinfo, askyesno  # For UserAgreementDialog
from threading import Thread  # To run Swing-like operations in separate threads

class GhidraApplicationConfiguration:
    USER_AGREEMENT_PROPERTY_NAME = "USER_AGREEMENT"
    SHOW_SPLASH_SCREEN = True

    def is_headless(self):
        return False

    def initialize_application(self):
        if self.SHOW_SPLASH_SCREEN:
            self.show_user_agreement()
            from PIL import Image  # For macOS taskbar icon
            image_path = ApplicationInformationDisplayFactory.get_largest_window_icon()
            Taskbar().setIconImage(Image.open(image_path))
        
        super().initialize_application()

    def platform_specific_fixups(self):
        if platform.system() == "Darwin":  # For macOS
            from tkinter import Tk as taskbar
            if taskbar().is_taskbar_supported():
                taskbar().set_icon_image(ApplicationInformationDisplayFactory.get_largest_window_icon())

    def show_user_agreement(self):
        value = Preferences.get_property(self.USER_AGREEMENT_PROPERTY_NAME)
        if "ACCEPT" == value:
            return
        
        thread = Thread(target=self.show_dialog, args=(True,))
        thread.start()

        # If we get here, then the user has accepted (if not, the system would have exited)
        Preferences.set_property(self.USER_AGREEMENT_PROPERTY_NAME, "ACCEPT")

    def show_dialog(self):
        dialog = UserAgreementDialog(True, True)
        from tkinter import Toplevel as DockingWindowManager
        dialog_window = DockingWindowManager()
        dialog_window.title("User Agreement")
        dialog_window.geometry("400x200")
        dialog_window.mainloop()

    def install_static_factories(self):
        super().install_static_factories()
        PluggableServiceRegistry.register_pluggable_service(ApplicationInformationDisplayFactory, GhidraApplicationInformationDisplayFactory)

    @property
    def show_splash_screen(self):
        return self.SHOW_SPLASH_SCREEN

    @show_splash_screen.setter
    def set_show_splash_screen(self, value):
        self.SHOW_SPLASH_SCREEN = value

    def get_error_display(self):
        return DockingErrorDisplay()
```

Please note that this is a translation of the Java code into Python and may not be exactly equivalent.