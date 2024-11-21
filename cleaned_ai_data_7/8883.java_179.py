class ChooseMatchTagAction:
    MENU_GROUP = "TAG_MENU_GROUP"
    EDIT_TAG_ICON = None  # Load image in actual implementation
    ACTION_NAME = "Choose Match Tag"

    def __init__(self, controller):
        self.controller = controller
        super().__init__(ACTION_NAME)
        self.setDescription("Choose Match Tag")
        self.setToolBarData({"icon": EDIT_TAG_ICON, "menu_group": MENU_GROUP})
        menu_data = {"name": ["Choose Tag"], "icon": EDIT_TAG_ICON, "menu_group": MENU_GROUP}
        menu_data["set_menu_subgroup"] = 1
        super().setPopupMenuData(menu_data)
        self.setEnabled(False)

    def actionPerformed(self, context):
        match_context = VTMatchContext(context) if isinstance(context, VTMatchContext) else None
        matches = [match for match in match_context.selected_matches] if match_context and match_context.selected_matches else []
        if not matches:
            return

        component = context.component_provider.get_component()
        self.edit_tag(matches, component)

    def edit_tag(self, matches, component):
        session = self.controller.session
        if not session:
            return

        dialog = TagChooserDialog(session, matches, component, None)
        SwingUtilities.invokeLater(lambda: self.controller.tool.show_dialog(dialog, component))
        last_tag = dialog.selected_tag

class VTMatchContext:
    def __init__(self, context):
        pass  # Assuming this is a wrapper for the Java context object

    @property
    def selected_matches(self):
        return []  # Replace with actual implementation


class TagChooserDialog:
    def __init__(self, session, matches, component, selected_tag=None):
        super().__init__("Choose Match Tag", True, True, True, False)
        self.session = session
        self.matches = matches
        self.component = component
        self.selected_tag = selected_tag

        panel = JPanel()
        tag_combobox = MatchTagComboBox(session, matches, component, selected_tag)

        # Replace with actual implementation for minimum size and action listener


    def get_selected_tag(self):
        return self.selected_tag


class MatchTagComboBox:
    def __init__(self, session, matches, component, selected_tag=None):
        pass  # Assuming this is a wrapper for the Java combo box object

    @property
    def selected_item(self):
        return None  # Replace with actual implementation

    def apply(self):
        pass  # Replace with actual implementation


class VTSession:
    def __init__(self, session):
        self.session = session
