import tkinter as tk
from typing import List

class DialogComponentProviderPopupActionManager:
    def __init__(self, provider):
        self.provider = provider
        self.popup_actions: List[DockingActionIf] = []

    def dispose(self):
        self.provider = None
        self.popup_actions.clear()

    def add_action(self, action: DockingActionIf):
        popup_menu_data = action.get_popup_menu_data()
        if popup_menu_data is None:
            return

        self.popup_actions.append(action)

    def popup_menu(self, action_context=None, e=tk.Event()):
        if e.is_consumed():
            return
        if action_context is None:
            action_context = ActionContext()

        # If the source is null, must set it or we won't have any popups shown.
        if action_context.get_source_object() is None:
            action_context.set_source_object(e.get_source())

        popup_menu_handler = PopupMenuHandler(action_context)

        docking_window_manager = DockingWindowManager(self.provider.get_component())
        if docking_window_manager is None:
            return

        action_to_gui_mapper = docking_window_manager.get_action_to_gui_mapper()
        menu_group_map = action_to_gui_mapper.get_menu_group_map()

        menu_mgr = MenuManager("Popup", '\0', None, True, popup_menu_handler, menu_group_map)
        self.populate_popup_menu_actions(docking_window_manager, menu_mgr, action_context)

        if not menu_mgr.is_empty():
            # Popup menu if items are available
            popup_menu = menu_mgr.get_popup_menu()
            c = e.get_source()
            popup_menu.add_popup_menu_listener(popup_menu_handler)
            popup_menu.show(c, e.get_x(), e.get_y())

    def populate_popup_menu_actions(self, docking_window_manager: DockingWindowManager,
                                     menu_mgr: MenuManager, action_context):
        # This is a bit of a kludge, but allows us to get generic actions, like 'copy' for tables.
        # This can go away if we ever convert DialogComponentProviders to use the primary action system
        # (this was something we were going to do once).  If that happens, then this entire class goes away.
        action_to_gui_mapper = docking_window_manager.get_action_to_gui_mapper()
        tool_popup_manager = action_to_gui_mapper.get_popup_action_manager()

        for local_action in self.popup_actions:
            tool_popup_manager.populate_popup_menu_actions(local_action, action_context, menu_mgr)


class PopupMenuHandler(tk.Menu):
    def __init__(self, action_context: ActionContext):
        super().__init__()
        self.action_context = action_context

    def item_entered(self, action: DockingActionIf):
        DockingWindowManager.set_mouse_over_action(action)

    def item_exited(self, action: DockingActionIf):
        DockingWindowManager.clear_mouse_over_help()

    def process_menu_action(self, action: DockingActionIf, event=tk.Event()):
        DockingWindowManager.clear_mouse_over_help()
        self.action_context.set_source_object(event.get_source())

        # this gives the UI some time to repaint before executing the action
        import threading

        thread = threading.Thread(target=lambda: (
            if action.is_enabled_for_context(self.action_context):
                if isinstance(action, ToggleDockingActionIf):
                    toggle_action = (ToggleDockingActionIf)action
                    toggle_action.set_selected(not toggle_action.get_selected())
                else:
                    action.perform_action(self.action_context)
        ))
        thread.start()
