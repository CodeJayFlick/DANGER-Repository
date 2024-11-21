class NextPreviousDataTypeAction:
    def __init__(self, provider, owner, is_next):
        self.is_next = is_next
        self.owner = owner
        self.provider = provider
        self.history = None

        if self.is_next:
            icon = Icons.RIGHT_ALTERNATE_ICON
        else:
            icon = Icons.LEFT_ALTERNATE_ICON

        self.set_tool_bar_data(ToolBarData(icon, "1_Navigation"))
        self.setDescription(
            f"{'Go to next data type in history' if is_next else 'Go to previous data type in history'}")
        self.set_help_location(HelpLocation("DataTypeManagerPlugin", "Navigation_Actions"))

    def actionPerformed(self, context):
        actions = self.get_action_list(context)
        action = actions[0]
        action.action_performed(context)
        self.provider.context_changed()

    def is_enabled_for_context(self, context):
        return not self.get_action_list(context).empty

    def get_action_list(self, context):
        return self.create_navigation_actions()

    def create_navigation_actions(self):
        last_dtm = None
        results = []
        types = (self.history.next_history_items() if self.is_next else self.history.previous_history_items())

        for url in types:
            dt = url.get_data_type(self.provider.get_plugin())
            if dt is None:  # The type may have been removed; maybe an undo happened. Leave the item in
                continue

            dtm = dt.get_data_type_manager()
            if dtm != last_dtm and results:
                results.append(HorizontalRuleAction(last_dtm, dtm))

            results.append(NavigationAction(url, dt))
            last_dtm = dtm

        return results


class NavigationAction(DockingAction):
    def __init__(self, url, dt):
        super().__init__("DataTypeNavigationAction_" + str(navigation_action_id_count), self.owner)
        self.url = url
        navigation_action_id_count += 1

        self.set_menu_bar_data(MenuData([dt.get_display_name()]))
        self.enabled = True
        self.help_location = HelpLocation("DataTypeManagerPlugin", "Navigation_Actions")


class HorizontalRuleAction(DockingAction):
    def __init__(self, top_name, bottom_name):
        super().__init__("Horizontal Rule Action")
        self.top_name = top_name
        self.bottom_name = bottom_name

    def action_performed(self, context):
        pass


navigation_action_id_count = 0
