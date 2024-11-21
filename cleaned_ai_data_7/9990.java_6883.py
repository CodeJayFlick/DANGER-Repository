import tkinter as tk

class DockingWindowManagerTestHelper:
    def get_popup_menu(self, dwm: 'DockingWindowManager', context):
        mapper = dwm.get_action_to_gui_mapper()
        popup_manager = mapper.get_popup_action_manager()
        popup = popup_manager.create_popup_menu(None, context)
        return popup
