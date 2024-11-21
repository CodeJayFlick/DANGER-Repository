class UndoAction:
    def __init__(self, controller):
        self.controller = controller
        super().__init__("Undo", VTPlugin.OWNER)
        help_location = HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Undo")
        set_help_location(help_location)

        menu_path = [ToolConstants.MENU_EDIT, "&Undo"]
        group = "ZZUndo"
        icon = ResourceManager.load_image("images/undo.png")

        menu_data = MenuData(menu_path, icon, group)
        menu_data.set_menu_sub_group("1Undo")  # make this appear above the redo menu item
        set_menubar_data(menu_data)

        tool_bar_data = ToolBarData(icon, group)
        set_toolbardata(tool_bar_data)

        description = "Undo"
        set_description(description)

        key_binding_data = KeyBindingData('Z', InputEvent.CTRL_MASK)
        set_keybindingdata(key_binding_data)

    def action_performed(self):
        session = self.controller.get_session()
        if session is None:
            return

        try:
            session.undo()
        except IOException as e:
            Msg.show_error(None, None, None, None, e)


class HelpLocation:
    def __init__(self, topic, name):
        pass


class MenuData:
    def __init__(self, menu_path, icon, group):
        self.menu_path = menu_path
        self.icon = icon
        self.group = group

    def set_menu_sub_group(self, sub_group):
        pass


class ToolBarData:
    def __init__(self, icon, group):
        self.icon = icon
        self.group = group


class KeyBindingData:
    def __init__(self, key, mask):
        self.key = key
        self.mask = mask


def action_performed(program_context):
    pass


def is_enabled_for_context(context):
    session = None

    if context.get_session() is not None and context.get_session().can_undo():
        name = context.get_session().get_name()
        set_menu_bar_data.set_item_name("Undo " + name)
        tip = HTMLUtilities.to_wrapped_html("Undo " + context.get_session().get_undo_name())
        set_description(tip)

    else:
        description = "Undo"
        get_menubar_data().set_item_name("Undo")
        return False

    return True
