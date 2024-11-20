class CompareFunctionsAction:
    def __init__(self):
        self.comparison_service = None  # equivalent to FunctionComparisonService in Java

    @staticmethod
    def get_comparison_icon():
        return "images/page_white_c.png"  # equivalent to ResourceManager.loadImage("images/page_white_c.png"); in Java

    @staticmethod
    def get_new_icon():
        return "images/bullet_star.png"  # equivalent to ResourceManager.loadImage("images/bullet_star.png"); in Java

    @staticmethod
    def get_scaled_new_icon(icon):
        return ScaledImageIconWrapper(icon, 16, 16)  # equivalent to new ScaledImageIconWrapper(NEW_ICON, 16, 16); in Java

    @staticmethod
    def get_translated_new_icon(icon):
        return TranslateIcon(icon, 4, -4)  # equivalent to new TranslateIcon(SCALED_NEW_ICON, 4, -4); in Java

    @staticmethod
    def get_create_new_comparison_icon():
        return MultiIcon(get_comparison_icon(), get_translated_new_icon(get_scaled_new_icon(get_new_icon())))  # equivalent to new MultiIcon(COMPARISON_ICON, TRANSLATED_NEW_ICON); in Java

    create_comparision_group = "A9_CreateComparison"  # equivalent to CREATE_COMPARISON_GROUP in Java
    popup_menu_name = "Compare Selected Functions"  # equivalent to POPUP_MENU_NAME in Java

    def __init__(self, tool, owner):
        super().__init__()
        self.comparison_service = tool.get_function_comparison_service()  # equivalent to this.comparisonService = tool.getService(FunctionComparisonService.class); in Java
        self.set_action_attributes()

    def action_performed(self, context):  # equivalent to public void actionPerformed(ActionContext context) { ... } in Java
        functions = get_selected_functions(context)
        if functions:
            self.comparison_service.compare_functions(functions)

    def is_enabled_for_context(self, context):
        return not (functions := get_selected_functions(context)).is_empty()  # equivalent to boolean isEnabledForContext(ActionContext actionContext) { ... } in Java

    def get_tool_bar_icon(self):  # equivalent to protected Icon getToolBarIcon() { ... } in Java
        return self.get_create_new_comparison_icon()

    @abstractmethod
    def get_selected_functions(self, context):
        pass  # equivalent to abstract Set<Function> getSelectedFunctions(ActionContext actionContext); in Java

    def set_action_attributes(self):  # equivalent to private void setActionAttributes() { ... } in Java
        self.description = "Create Function Comparison"
        menu_data = MenuData(["Compare Selected Functions"], self.get_tool_bar_icon(), self.create_comparision_group)
        self.set_popup_menu_data(menu_data)

        tool_bar_data = ToolBarData(self.get_tool_bar_icon(), self.create_comparision_group)
        self.set_tool_bar_data(tool_bar_data)

        help_location = HelpLocation("FunctionComparison", "Function_Comparison")
        self.set_help_location(help_location)

        key_binding_data = KeyBindingData('C', InputEvent.SHIFT_DOWN_MASK)
        self.set_key_binding_data(key_binding_data)


class MenuData:
    def __init__(self, items, icon=None, group=""):
        self.items = items
        self.icon = icon
        self.group = group


class ToolBarData:
    def __init__(self, icon, group):
        self.icon = icon
        self.group = group


class HelpLocation:
    def __init__(self, topic, subtopic):
        self.topic = topic
        self.subtopic = subtopic


class KeyBindingData:
    def __init__(self, key_char, modifiers):
        self.key_char = key_char
        self.modifiers = modifiers

# This is the main class that extends CompareFunctionsAction
class MyCompareFunctionsAction(CompareFunctionsAction):
    pass  # You need to implement get_selected_functions method here


if __name__ == "__main__":
    my_action = MyCompareFunctionsAction()
