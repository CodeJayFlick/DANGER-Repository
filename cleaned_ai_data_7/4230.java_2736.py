class GhidraScriptActionManager:
    RERUN_LAST_SHARED_ACTION_NAME = "Rerun Last Script"
    RESOURCE_FILE_ACTION_RUN_GROUP = "1"

    def __init__(self, provider: 'GhidraScriptComponentProvider', plugin: 'GhidraScriptMgrPlugin',
                 info_manager: 'GhidraScriptInfoManager'):
        self.provider = provider
        self.plugin = plugin
        self.info_manager = info_manager
        self.create_actions()

    def dispose(self):
        for action in list(self.action_map.values()):
            action.dispose()
        self.action_map.clear()

    def restore_user_defined_keybindings(self, save_state: 'SaveState'):
        dirs = self.provider.get_bundle_host().get_bundle_files()
        names = save_state.get_names()

        for name in names:
            for dir in dirs:
                script = ResourceFile(dir, name)
                if not script.exists():
                    continue

                action = self.create_action(script)
                stroke_str = save_state.get_string(name, None)
                if stroke_str is None or len(stroke_str) == 0:
                    action.set_key_binding_data(None)
                else:
                    stroke = KeyBindingUtils.parse_key_stroke(stroke_str)
                    if stroke is not None:
                        action.set_key_binding_data(KeyBindingData(stroke))
        return

    def restore_scripts_that_are_in_tool(self, save_state: 'SaveState'):
        script_paths = set()
        for file in self.action_map.keys():
            script_paths.add(generic.util.Path.to_path_string(file))

        array = list(script_paths)
        save_state.put_strings("Scripts_Actions_Key", array)

    def save_user_defined_keybindings(self, save_state: 'SaveState'):
        actions = list(self.action_map.values())
        for action in actions:
            if not action.is_user_defined_key_binding():
                continue

            script_file = action.get_script()
            info = self.info_manager.get_existing_script_info(script_file)
            if info is None:
                Msg.show_error(self, "Bad state?", "action associated with a script that has no info")
                continue

            stroke = action.get_key_binding()
            if stroke is not None:
                save_state.put_string(script_file.name, KeyBindingUtils.parse_key_stroke(stroke))
        return

    def create_action(self, name: str, menu_entry: str, description: str,
                      icon: 'Icon', tool_bar_group: str = None) -> 'DockingAction':
        action = ActionBuilder(name, self.plugin.get_name()).popup_menu_path(menu_entry).popup_menu_icon(icon)
        if tool_bar_group is not None:
            action.tool_bar_icon(icon).tool_bar_group(tool_bar_group)

        return action

    def create_script_action(self, name: str, menu_entry: str, description: str,
                             icon: 'Icon', tool_bar_group: str = None) -> 'DockingAction':
        return self.create_action(name, menu_entry, description, icon, tool_bar_group)

    def notify_script_was_run(self):
        new_desc = "Rerun " + self.provider.get_last_run_script().name
        run_last_action.fire_property_changed("description", "", new_desc)
        global_run_last_action.fire_property_changed("description", "", new_desc)

    # ... rest of the class definition ...
