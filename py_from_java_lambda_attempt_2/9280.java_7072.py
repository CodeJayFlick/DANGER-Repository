Here is the translation of the Java code into Python:

```Python
class AbstractDockingTool:
    def __init__(self):
        self.win_mgr = None
        self.tool_actions = None
        self.options_map = {}
        self.config_changed_flag = False

    def is_visible(self):
        return self.win_mgr.is_visible()

    def set_visible(self, visibility):
        self.win_mgr.set_visible(visibility)

    def to_front(self):
        frame = self.win_mgr.get_root_frame()
        if frame.get_extended_state() == Frame.ICONIFIED:
            frame.set_extended_state(Frame.NORMAL)
        frame.to_front()

    def add_component_provider(self, provider, show):
        r = lambda: self.win_mgr.add_component(provider, show) and \
              self.tool_actions.add_global_action(provider.show_provider_action())
        Swing.run_now(r)

    def remove_component_provider(self, provider):
        r = lambda: (self.tool_actions.remove_global_action(provider.show_provider_action()) 
                    and self.tool_actions.remove_actions(provider)
                    and self.win_mgr.remove_component(provider))
        Swing.run_now(r)

    def get_component_provider(self, name):
        return self.win_mgr.get_component_provider(name)

    def set_status_info(self, text):
        self.win_mgr.set_status_text(text)

    def set_status_info(self, text, beep):
        self.win_mgr.set_status_text(text)
        if beep:
            tk = self.get_tool_frame().get_toolkit()
            tk.beep()

    def clear_status_info(self):
        self.win_mgr.set_status_text("")

    def add_action(self, action):
        self.tool_actions.add_global_action(action)

    def remove_action(self, action):
        self.tool_actions.remove_global_action(action)

    def add_local_action(self, provider, action):
        self.tool_actions.add_local_action(provider, action)

    def remove_local_action(self, provider, action):
        self.tool_actions.remove_local_action(provider, action)

    def get_all_actions(self):
        return self.tool_actions.get_all_actions()

    def add_popup_action_provider(self, provider):
        self.win_mgr.add_popup_action_provider(provider)

    def remove_popup_action_provider(self, provider):
        self.win_mgr.remove_popup_action_provider(provider)

    def get_docking_actions_by_owner_name(self, owner):
        return self.tool_actions.get_actions(owner)

    def get_active_component_provider(self):
        return self.win_mgr.get_active_component_provider()

    def show_component_provider(self, provider, visible):
        r = lambda: self.win_mgr.show_component(provider, visible)
        Swing.run_now(r)

    def show_dialog(self, dialog_component):
        DockingWindowManager.show_dialog(None, dialog_component)

    def get_tool_frame(self):
        return self.win_mgr.get_root_frame()

    def get_provider_window(self, provider):
        return self.win_mgr.get_provider_window(provider)

    def to_front(self, provider):
        r = lambda: self.win_mgr.to_front(provider)
        Swing.run_now(r)

    def is_visible(self, provider):
        return self.win_mgr.is_visible(provider)

    def is_active(self, provider):
        return self.win_mgr.is_active_provider(provider)

    def update_title(self, provider):
        self.win_mgr.update_title(provider)

    def set_menu_group(self, menu_path, group, menu_subgroup=None):
        self.win_mgr.set_menu_group(menu_path, group, menu_subgroup)

    def context_changed(self, provider):
        self.win_mgr.context_changed(provider)

    def add_context_listener(self, listener):
        self.win_mgr.add_context_listener(listener)

    def remove_context_listener(self, listener):
        self.win_mgr.remove_context_listener(listener)

    def get_window_manager(self):
        return self.win_mgr

    def set_config_changed(self, changed):
        self.config_changed_flag = changed

    def has_config_changed(self):
        return self.config_changed_flag

    def get_tool_actions(self):
        return self.tool_actions
```

Note: The `Swing` class is not a built-in Python module. It seems to be used for running tasks in the Swing event dispatch thread, similar to how you would use the EventQueue.invokeLater method in Java. If this code is meant to run on a desktop application with a GUI, then it might need some modifications or additional modules (like `tkinter` or `PyQt`) to work properly.