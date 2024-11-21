class CreateImpliedMatchAction:
    def __init__(self, controller: 'VTController', provider: 'VTImpliedMatchesTableProvider'):
        super().__init__("Accept Implied Match", VTPlugin.OWNER)
        self.controller = controller
        self.provider = provider

        icon = ResourceManager.load_image("images/flag.png")
        self.set_tool_bar_data(ToolBarData(icon, "1"))
        self.set_popup_menu_data(MenuData(["Accept Implied Match"], icon, "1"))
        self.set_help_location(HelpLocation("VersionTrackingPlugin", "Accept_Implied_Match"))
        self.setEnabled(False)

    def actionPerformed(self, context: 'ActionContext'):
        matches = self.provider.get_selected_implied_matches()

        my_task = CreateImpliedMatchesTask(self.controller, matches)
        my_task.add_task_listener(TaskListener(
            lambda task: print("task completed"),
            lambda task: print("task cancelled")
        ))
        self.controller.run_vt_task(my_task)

    def is_enabled_for_context(self, context: 'ActionContext'):
        return len(self.provider.get_selected_implied_matches()) > 0

    def is_add_to_popup(self, context: 'ActionContext'):
        return True
