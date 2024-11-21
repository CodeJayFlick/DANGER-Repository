Here is a translation of the Java code into Python:

```Python
class MultipleActionDockingToolbarButton:
    def __init__(self, action):
        self.multiple_action = action
        self.install_mouse_listeners()
        self.set_icon(ResourceManager.load_image("images/core.png"))

    def set_border(self, border):
        super().set_border(border)
        if self.primary_icon is not None:  # happens during init
            self.init_icons()

    def set_icon(self, icon):
        self.primary_icon = Objects.requireNonNull(icon)
        self.init_icons()

    def get_disabled_icon(self):
        return self.disabled_icon

    def set_perform_action_on_button_click(self, perform_action_on_button_click):
        self.entire_button_shows_popup_menu = not perform_action_on_button_click
        self.icon_border_enabled = perform_action_on_button_click
        self.popup_context = self.create_popup_context()

    @staticmethod
    def create_image_icon():
        return IconWithDropDownArrow(ResourceManager.load_image("images/core.png"), 0, 0)

    @staticmethod
    def create_popup_context():
        if not self.entire_button_shows_popup_menu:
            return Rectangle(0, 0, get_width(), get_height())
        border = get_border()
        insets = border.get_border_inches(self) if border else new Insets(0, 0, 0, 0)
        left_icon_width = self.primary_icon.get_icon_width() + (insets.left + insets.right)
        right_button_width = ARROW_WIDTH + ARROW_PADDING + (insets.left + insets.right)
        height = get_icon().get_icon_height() + insets.top + insets.bottom
        return Rectangle(left_icon_width, 0, right_button_width, height)

    def show_popup(self):
        menu = JPopupMenu()
        action_list = self.multiple_action.get_actions(get_action_context())
        for docking_action in action_list:
            if not docking_action.is_enabled():
                name = docking_action.get_name()
                description = docking_action.get_description()
                separator = ProgramNameSeparator(name, description)
                menu.add(separator)
                continue
            item = docking_action.create_menu_item(False)
            item.set_ui((item.get_ui()))
            delegate_action = docking_action
            item.add_listener(lambda e: self.action_performed(e))
        if listener is not None:
            menu.add_popup_listeners(listener)
        p = get_popup_point()
        menu.show(self, p.x, p.y)

    def action_performed(self):
        context = get_action_context()
        for action in actions:
            action.perform(context)

    @staticmethod
    def create_icon_with_dropdown_arrow(base_icon, width, height, insets):
        return IconWithDropDownArrow(base_icon, width, height, insets)

class PopupMouseListener(MouseAdapter, PopupMenuListener):
    def __init__(self, parent_listeners):
        self.parent_listeners = parent_listeners

    @staticmethod
    def create_popup_context():
        if not popup_is_showing() and e.get_click_count() == 1:
            return None
        long event_time = System.currentTimeMillis()
        if action_id == event_time:
            return None
        click_point = e.get_point()
        if self.is_enabled() and popup_context.contains(click_point):
            Swing.invokeLater(lambda: show_popup(self))
            e.consume()

    def mouse_pressed(self, e):
        for listener in parent_listeners:
            listener.mouse_pressed(e)

class HoverChangeListener(ChangeListener):
    def __init__(self, delegate_action):
        self.delegate_action = delegate_action

    @staticmethod
    def create_hover_change_listener(delegate_action):
        return HoverChangeListener(delegate_action)
```

Please note that Python does not have direct equivalents for Java's Swing and AWT classes. The above code is a translation of the original Java code into Python, but it may require some modifications to work correctly in a Python environment.