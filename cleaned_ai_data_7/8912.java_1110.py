import tkinter as tk
from tkinter import messagebox

class ResetMarkupItemAction:
    RESET_ICON = None  # Initialize with None for now.
    MENU_GROUP = "VTPlugin.UNEDIT_MENU_GROUP"

    def __init__(self, controller, add_to_toolbar):
        self.controller = controller
        super().__init__("Reset Mark-up", VTPlugin.OWNER)
        
        if add_to_toolbar:
            set_tool_bar_data(ToolBarData(RESET_ICON, MENU_GROUP))
        set_popup_menu_data(MenuData(["Reset Mark-up"], RESET_ICON, MENU_GROUP))
        self.enabled = False  # Initialize with false.
        help_location = HelpLocation("VersionTrackingPlugin", "Reset_Markup_Item")
        
    def action_performed(self):
        session = controller.get_session()
        markup_items = controller.get_markup_items()
        correlation = get_correlation()
        task = UnapplyMarkupItemTask(session, correlation, markup_items)
        task.add_task_listener(TaskListener(task_completed=task.completed,
                                             task_cancelled=lambda t: None))
        
    def get_correlation(self):
        match_info = self.controller.get_match_info()
        if not match_info:
            return None
        
        association_type = match_info.match.association.type
        if association_type == VTAssociationType.FUNCTION:
            source_function, destination_function = match_info.source_function, match_info.destination_function
            correlator = self.controller.correlate(source_function, destination_function)
            
        elif association_type == VTAssociationType.DATA:
            source_data, destination_data = match_info.source_data, match_info.destination_data
            correlator = self.controller.correlate(source_data, destination_data)
        
    def is_enabled_for_context(self):
        markup_items = controller.get_markup_items()
        if not markup_items:
            return False
        
        for item in markup_items:
            if not can_reset(item):
                return False
            
        return True
    
    # Somewhat kludgy method to know when an item will have been put into the database and 
    # that we can undo that
    def can_reset(self, markup_item):
        address_source = markup_item.destination_address_source
        
        if VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE == address_source:
            return True  # We can undo user defined addresses.
        
        status = markup_item.status
        return not status.is_default()  # This handled applied status and user-defined status.

    def is_add_to_popup(self):
        return self.enabled

class ToolBarData:
    def __init__(self, icon, menu_group):
        self.icon = icon
        self.menu_group = menu_group

class MenuData:
    def __init__(self, items, icon, menu_group):
        self.items = items
        self.icon = icon
        self.menu_group = menu_group

class HelpLocation:
    def __init__(self, plugin_name, help_topic):
        self.plugin_name = plugin_name
        self.help_topic = help_topic

# Initialize the RESET_ICON here.
ResetMarkupItemAction.RESET_ICON = tk.PhotoImage(file="images/undo-apply.png")

controller = None  # You need to initialize this with your controller object.

action = ResetMarkupItemAction(controller, True)
