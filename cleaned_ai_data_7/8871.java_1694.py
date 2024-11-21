class AbstractManualMatchFromToolsAction:
    def __init__(self, plugin: 'VTPlugin', name: str):
        self.plugin = plugin
        super().__init__(name)

    def actionPerformed(self, context: dict) -> None:
        source_function = self.sub_tool_context.get_source_function()
        destination_function = self.sub_tool_context.get_destination_function()

        if not self.validate_selected_functions(source_function, destination_function):
            return

        controller = self.plugin.get_controller()
        if not self.validate_existing_match(controller):
            return

        if not self.validate_cursor_position():
            return

        task = self.get_task(controller, source_function, destination_function)

        def on_task_completed(task: 'Task') -> None:
            controller.set_selected_match(task.get_new_match())

        def on_task_cancelled(task: 'Task') -> None:
            pass  # don't care; nothing to do

        task.add_listener(on_task_completed)
        task.add_listener(on_task_cancelled)

        self.plugin.get_controller().run_vt_task(task)

    @abstractmethod
    def get_task(self, controller: 'VTController', source_function: 'Function',
                 destination_function: 'Function') -> 'CreateManualMatchTask':
        pass

    def validate_selected_functions(self, source_function: 'Function',
                                      destination_function: 'Function') -> bool:
        if not all([source_function, destination_function]):
            Msg.show_info('Cannot Create Match', "The current location must be inside of a function in both the source and "
                                                  "destination programs")
            return False
        return True

    def validate_existing_match(self, controller: 'VTController') -> bool:
        match = self.sub_tool_context.get_match()
        if match is not None:
            choice = OptionDialog.show_option_no_cancel_dialog(None,
                                                                 "Match Exists",
                                                                 "<html>You have attempted to create a manual when "
                                                                 "a match already exists.<br>"
                                                                 "Would you like to select the match in the matches table?",
                                                                 'Yes', 'No',
                                                                 OptionDialog.QUESTION_MESSAGE)
            if choice == 1:
                controller.set_selected_match(match)
        return False

    def validate_cursor_position(self) -> bool:
        source_cursor_on_screen = self.sub_tool_context.is_source_cursor_on_screen()
        destination_cursor_on_screen = self.sub_tool_context.is_destination_cursor_on_screen()

        if all([source_cursor_on_screen, destination_cursor_on_screen]):
            return True
        message = ''
        if not source_cursor_on_screen:
            message += '  <b>source tool</b>'
        if not destination_cursor_on_screen:
            message += ' and the  <b>destination tool</b>'
        choice = OptionDialog.show_option_no_cancel_dialog(None,
                                                             "Cursor Offscreen",
                                                             "<html>Your cursor is off the screen in the "
                                                             + message +
                                                             ".<br>"
                                                             "There is a chance the cursor is not in the function you "
                                                             "currently see.<br>Would you like to continue creating a match?",
                                                             'Yes', 'No',
                                                             OptionDialog.QUESTION_MESSAGE)
        if choice != 1:
            return False
        return True

    def is_enabled_for_context(self, context: dict) -> bool:
        return isinstance(context.get('context'), CodeViewerActionContext)

    def is_add_to_popup(self, context: dict) -> bool:
        if not isinstance(context.get('context'), CodeViewerActionContext):
            return False
        self.sub_tool_context = SubToolContext(self.plugin)
        source_function = self.sub_tool_context.get_source_function()
        destination_function = self.sub_tool_context.get_destination_function()
        match = self.sub_tool_context.get_match()
        return all([source_function, destination_function]) and not bool(match)

class VTPlugin:
    def get_controller(self) -> 'VTController':
        pass

class SubToolContext:
    def __init__(self, plugin: 'VTPlugin'):
        self.plugin = plugin
        # Initialize the source function, destination function, and match here.

    def is_source_cursor_on_screen(self) -> bool:
        pass  # Implement this method to check if the cursor is on screen in the source tool

    def get_source_function(self) -> 'Function':
        pass  # Implement this method to return the current source function

    def is_destination_cursor_on_screen(self) -> bool:
        pass  # Implement this method to check if the cursor is on screen in the destination tool

    def get_destination_function(self) -> 'Function':
        pass  # Implement this method to return the current destination function

    def get_match(self) -> 'VTMatch':
        pass  # Implement this method to return the match
