class PreviousFunctionAction:
    FUNCTION_NAVIGATE_GROUP = "A9_FunctionNavigate"
    PREVIOUS_ICON = ResourceManager.load_image("images/arrow_up.png", 3, 1)
    FUNCTION_ICON = ResourceManager.load_image("images/FunctionScope.gif", -5, -2)
    PREVIOUS_FUNCTION_ICON = MultiIcon(PREVIOUS_ICON, FUNCTION_ICON)

    def __init__(self, provider):
        super().__init__("Compare Previous Function", provider.get_owner())

        self.set_key_binding_data(
            KeyBindingData('P', InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)
        )
        self.setDescription("Compare the previous function for the side with focus.")
        self.set_popup_menu_data(
            MenuData(["Compare The Previous Function"], PREVIOUS_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP)
        )

        new_tool_bar_data = ToolBarData(PREVIOUS_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP)
        self.set_toolbar_data(new_tool_bar_data)

        help_location = HelpLocation(MultiFunctionComparisonPanel.HELP_TOPIC, "Navigate Previous")
        self.set_help_location(help_location)

    def is_enabled_for_context(self, context):
        if not isinstance(context.get_component_provider(), MultiFunctionComparisonProvider):
            return False

        provider = context.get_component_provider()
        component = provider.get_component()

        if not isinstance(component, MultiFunctionComparisonPanel):
            return False

        panel = component
        focused_component = panel.get_focused_component()

        return focused_component.get_selected_index() > 0

    def action_performed(self, context):
        provider = context.get_component_provider()
        panel = provider.get_component()
        focused_component = panel.get_focused_component()

        focused_component.set_selected_index(focused_component.get_selected_index() - 1)
