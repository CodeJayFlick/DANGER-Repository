class ToggleExpandCollapseDataAction:
    def __init__(self, provider):
        self.provider = provider
        super().__init__("Toggle Expand/Collapse Data", provider.get_owner())
        
        menu_data = MenuData(["Toggle Expand/Collapse Data"], None, "Structure")
        key_binding_data = KeyBindingData(' ', 0)
        help_location = HelpLocation("CodeBrowserPlugin", "ExpandCollapseActions")
        description = f"Opens or closes the component data for this location or if on a non-component data in another data component, then closes the parent component."
        
        self.set_popup_menu_data(menu_data)
        self.set_key_binding_data(key_binding_data)
        self.set_help_location(help_location)
        self.set_description(description)
        self.enabled = True

    def is_enabled_for_context(self, context):
        location = context.get_location()
        data = get_closest_component_data_unit(location)
        
        if data is None:
            return False
        
        return True

    def action_performed(self, context):
        listing_panel = self.provider.get_listing_panel()
        layout_model = listing_panel.get_listing_model()

        program_location = context.get_location()
        data = get_closest_component_data_unit(program_location)

        task_launcher(new OpenCloseDataTask(data, layout_model), listing_panel)


def get_closest_component_data_unit(location):
    if location is None:
        return None

    data = DataUtilities.get_data_at_location(location)
    
    if data is None:
        return None
    
    if data.get_num_components() > 0:
        return data
    else:
        return data.get_parent()


class OpenCloseDataTask(Task):
    def __init__(self, data, model):
        super().__init__("Open/Close Data In Selection", True, True, True, True)
        
        self.data = data
        self.model = model

    def run(self, monitor):
        if not self.model.is_open(self.data):
            self.model.open_data(self.data)
        else:
            self.model.close_data(self.data)


class Task:
    pass


def new(task):
    return task
