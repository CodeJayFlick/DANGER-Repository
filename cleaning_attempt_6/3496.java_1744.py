import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import simpledialog

class ClipboardPlugin:
    def __init__(self):
        self.clipboard_owner_provider = None
        self.service_action_map = {}
        self.last_used_copy_special_type = {}

    def dispose(self):
        for service in list(self.service_action_map.keys()):
            self.remove_local_actions(service)
        super().dispose()

    def program_deactivated(self, program):
        if self.clipboard_owner_provider:
            self.clipboard_owner_provider.lost_ownership(None)

    def register_clipboard_content_provider(self, clipboard_service):
        self.initialize_local_actions(clipboard_service)
        clipboard_service.add_change_listener(self)

    def deregister_clipboard_content_provider(self, clipboard_service):
        action_list = self.service_action_map.get(clipboard_service)
        if action_list:
            self.remove_local_actions(clipboard_service, action_list)
        del self.service_action_map[clipboard_service]
        clipboard_service.remove_change_listener(self)

    def initialize_local_actions(self, clipboard_service):
        # Don't add the actions twice
        list = self.service_action_map.get(clipboard_service)
        if list:
            return

        action_list = self.create_actions(clipboard_service)
        self.service_action_map[clipboard_service] = action_list
        self.add_local_actions(clipboard_service, action_list)

    def add_local_actions(self, clipboard_service, action_list):
        component_provider = clipboard_service.get_component_provider()
        for plugin_action in action_list:
            tool.add_local_action(component_provider, plugin_action)

    def remove_local_actions(self, clipboard_service, action_list):
        if not self.tool:
            return  # Can happen during closing the tool

        component_provider = clipboard_service.get_component_provider()
        for plugin_action in action_list:
            tool.remove_local_action(component_provider, plugin_action)

    def create_actions(self, clipboard_service):
        list = []
        if clipboard_service.enable_copy():
            list.append(CopyAction(clipboard_service))
        if clipboard_service.enable_copy_special():
            list.extend([CopySpecialAction(clipboard_service), CopySpecialAgainAction(clipboard_service)])
        if clipboard_service.enable_paste():
            list.append(PasteAction(clipboard_service))

        return list

    def lost_ownership(self, clipboard, contents):
        self.clipboard_owner_provider = None
        update_paste_state()

    def set_clipboard_contents(self, system_clipboard, transferable):
        system_clipboard.set_contents(transferable)
        is_clipboard_owner = True

    def clear_clipboard_contents(self):
        if not is_clipboard_owner:
            return  # Can happen during closing the tool
        clipboard = get_system_clipboard()
        set_clipboard_contents(clipboard, DummyTransferable())

    def update_copy_state(self):
        for service in self.service_action_map.keys():
            action_list = self.service_action_map[service]
            for plugin_action in action_list:
                if isinstance(plugin_action, ICopy):
                    plugin_action.set_enabled(service.can_copy())

    def update_paste_state(self):
        clipboard = get_system_clipboard()
        data_flavors = get_available_data_flavors(clipboard)
        for service in self.service_action_map.keys():
            action_list = self.service_action_map[service]
            for plugin_action in action_list:
                if isinstance(plugin_action, IPaste):
                    plugin_action.set_enabled(service.can_paste(data_flavors))

    def copy(self, clipboard_service):
        task = Task("Copying", True, False, True)
        monitor = task.get_monitor()
        monitor.set_message("Setting Clipboard Contents")
        transferable = clipboard_service.copy(monitor)
        if transferable:
            set_clipboard_contents(get_system_clipboard(), transferable)

    def paste(self, clipboard_service):
        window_manager = DockingWindowManager.get_active_instance()
        active_window = window_manager.get_active_window()
        task_launcher = TaskLauncher(Task("Pasting", False, True), active_window)
        self.clipboard_owner_provider = None

    def copy_special(self, clipboard_service, type, prompt=True):
        new_type = type
        available_types = clipboard_service.current_copy_types
        if not available_types:
            if prompt:
                messagebox.show_error(
                    "Error", "There are no copy formats available"
                )
            else:
                tool.set_status_info("There are no copy formats available")
            return

        if prompt:
            dialog = CopyPasteSpecialDialog(self, available_types, "Copy Special")
            component_provider = clipboard_service.get_component_provider()
            tool.show_dialog(dialog, component_provider)
            new_type = dialog.get_selected_type()

        self.last_used_copy_special_type[clipboard_service] = new_type
        task = Task("Copying", True, False, True)
        monitor = task.get_monitor()
        monitor.set_message("Setting Clipboard Contents")
        transferable = clipboard_service.copy_special(new_type, monitor)
        if transferable:
            set_clipboard_contents(get_system_clipboard(), transferable)

    def get_system_clipboard(self):
        return GClipboard.get_system_clipboard()

class CopyAction(DockingAction, ICopy):
    def __init__(self, clipboard_service):
        super().__init__("Copy", "Clipboard")
        self.clipboard_service = clipboard_service
        set_popup_menu_data(MenuData(["Copy"], "Clipboard"))
        set_tool_bar_data(
            ToolBarData(ResourceManager.load_image("images/page_white_copy.png"), "Clipboard"),
            True,
        )
        set_key_binding_data(KeyBindingData(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK))
        set_help_location(HelpLocation("ClipboardPlugin", "Copy"))

    def actionPerformed(self, context):
        self.copy(self.clipboard_service)

class PasteAction(DockingAction, IPaste):
    def __init__(self, clipboard_service):
        super().__init__("Paste", "Clipboard")
        self.clipboard_service = clipboard_service
        set_popup_menu_data(MenuData(["Paste"], "Clipboard"))
        set_tool_bar_data(
            ToolBarData(ResourceManager.load_image("images/page_paste.png"), "Clipboard"),
            True,
        )
        set_key_binding_data(KeyBindingData(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK))
        set_help_location(HelpLocation("ClipboardPlugin", "Paste"))

    def actionPerformed(self, context):
        self.paste(self.clipboard_service)

class CopySpecialAction(DockingAction, ICopy):
    def __init__(self, clipboard_service):
        super().__init__("Copy Special", "Clipboard")
        self.clipboard_service = clipboard_service
        set_popup_menu_data(MenuData(["Copy Special..."], "Clipboard"))
        set_enabled(False)
        set_help_location(HelpLocation("ClipboardPlugin", "Copy_Special"))

    def actionPerformed(self, context):
        self.copy_special(self.clipboard_service, None, True)

class CopySpecialAgainAction(DockingAction, ICopy):
    def __init__(self, clipboard_service):
        super().__init__("Copy Special Again", "Clipboard")
        self.clipboard_service = clipboard_service
        set_popup_menu_data(MenuData(["Copy Special Again"], "Clipboard"))
        set_enabled(False)
        set_help_location(HelpLocation("ClipboardPlugin", "Copy_Special"))

    def actionPerformed(self, context):
        self.copy_special(self.clipboard_service, last_used_copy_special_type.get(clipboard_service), False)

class DummyTransferable:
    def get_transfer_data(self, flavor) -> object:
        return None

    def get_transfer_data_flavors(self) -> list[DataFlavor]:
        return []

    def is_data_flavor_supported(self, flavor: DataFlavor) -> bool:
        return True
