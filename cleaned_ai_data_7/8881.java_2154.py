import tkinter as tk
from PIL import ImageTk, Image

class AutoVersionTrackingAction:
    AUTO_VT_ICON = None  # Load icon from resources later

    def __init__(self):
        self.controller = VTController()  # Assuming this is a class or instance variable in the original code
        
        super().__init__("Automatic Version Tracking", "VTPlugin.OWNER")
        
        menu_path = [ToolConstants.MENU_FILE, "Automatic Version Tracking"]
        set_menu_bar_data(menu_path, AUTO_VT_ICON, "AAA")
        set_tool_bar_data(AUTO_VT_ICON, "View")

    def is_enabled_for_context(self):
        session = self.controller.get_session()
        return session is not None

    def action_performed(self):
        session = self.controller.get_session()

        # In the future we might want to make these user options so the user can change them 
        command = AutoVersionTrackingCommand(self, session, 1.0, 10.0)
        
        self.controller.get_tool().execute_background_command(command, session)

class VTController:
    def __init__(self):
        pass

    def get_session(self):
        return None  # Assuming this method returns a valid session in the original code
