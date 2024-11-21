class ExpandAllDataAction:
    def __init__(self, provider):
        self.provider = provider
        super().__init__("Expand All Data", provider.get_owner())
        set_popup_menu_data(["Expand All Data"], None, "Structure")
        description("Open all data recursively from the current location downward.")
        help_location(HelpLocation("CodeBrowserPlugin", "ExpandCollapseActions"))
        enabled(True)
        add_to_window_when(ProgramLocationActionContext)

    def is_enabled_for_context(self, context):
        if context.get_selection() and not context.get_selection().empty:
            update_popup_menu_name(True)
            return True
        component_data = get_component_data(context.get_location())
        if component_data is None:
            return False

        update_popup_menu_name(False)
        return True

    def action_performed(self, context):
        model = self.provider.get_listing_panel().get_listings_model()
        selection = context.get_selection()
        if selection and not selection.empty:
            TaskLauncher.launch_modal("Expand Data In Selection",
                lambda monitor: model.open_all_data(selection, monitor))
            return
        location = context.get_location()
        data = get_component_data(location)
        TaskLauncher.launch_modal("Expand Data In Selection",
            lambda monitor: model.open_all_data(data, monitor))

    def update_popup_menu_name(self, has_selection):
        if has_selection:
            self.popup_menu_data.set_menu_path(["Expand All Data In Selection"])
            description("Open all data recursively in the current selection.")
        else:
            self.popup_menu_data.set_menu_path(["Expand All Data"])
            description("Open all data recursively from the current location downward.")

    def get_model(self):
        return self.provider.get_listing_panel().get_listings_model()

    def get_component_data(self, location):
        if not location:
            return None
        data = DataUtilities.get_data_at_location(location)
        if not data or data.num_components <= 0:
            return None

        return data


class HelpLocation:
    def __init__(self, plugin_name, action_name):
        self.plugin_name = plugin_name
        self.action_name = action_name

    def get_plugin_name(self):
        return self.plugin_name

    def get_action_name(self):
        return self.action_name


# usage example
provider = CodeViewerProvider()
action = ExpandAllDataAction(provider)
