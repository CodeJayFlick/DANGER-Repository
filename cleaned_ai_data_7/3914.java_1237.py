class AbstractApplyFunctionSignatureAction:
    MENU_GROUP = "A0_Apply"
    HELP_TOPIC = "FunctionComparison"
    ACTION_NAME = "Apply Function Signature To Other Side"

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

        description = f"Apply the signature of the function in the currently active side of a code comparison panel to the function in the other side of the panel."
        menu_data = {"name": ACTION_NAME}
        set_description(description)
        set_menu_data(menu_data)
        set_enabled(True)
        set_help_location(HELP_TOPIC, ACTION_NAME)

    def is_add_to_popup(self, context):
        return True

    def is_enabled_for_context(self, context):
        if isinstance(context, CodeComparisonPanelActionContext):
            code_comparison_panel = context.get_code_comparison_panel()
            left_function = code_comparison_panel.left_function
            right_function = code_comparison_panel.right_function
            if not (left_function and right_function):
                return False  # Can only apply if both sides have functions.
        return True

    def action_performed(self, context):
        if isinstance(context, CodeComparisonPanelActionContext):
            code_comparison_panel = context.get_code_comparison_panel()
            left_function = code_comparison_panel.left_function
            right_function = code_comparison_panel.right_function
            component_provider = context.component_provider
            left_has_focus = code_comparison_panel.left_panel_has_focus

            commit = self.update_function(component_provider, right_function if not left_has_focus else left_function)
            if commit:
                # Refresh the side that had its function signature changed (the side without focus).
                if left_has_focus:
                    code_comparison_panel.refresh_right_panel()
                else:
                    code_comparison_panel.refresh_left_panel()

    def has_read_only_non_focused_side(self, code_comparison_panel):
        left_function = code_comparison_panel.left_function
        right_function = code_comparison_panel.right_function

        if not (left_function and right_function):
            return False  # Doesn't have a function on both sides.

        left_has_focus = code_comparison_panel.left_panel_has_focus
        program_left = left_function.get_program()
        program_right = right_function.get_program()

        return not left_has_focus and program_left.domain_file.is_read_only() or (left_has_focus and program_right.domain_file.is_read_only())

    def update_function(self, provider, destination_function, source_function):
        try:
            FunctionUtility.update_function(destination_function, source_function)
            commit = True
        except InvalidInputException | DuplicateNameException as e:
            message = f"Couldn't apply the function signature from {source_function.name} to {destination_function.name} at {destination_function.entry_point}. {e}"
            print(message)

        return commit

class CodeComparisonPanelActionContext:
    def __init__(self, code_comparison_panel):
        self.code_comparison_panel = code_comparison_panel
