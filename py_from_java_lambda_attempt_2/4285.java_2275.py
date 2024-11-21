Here is the translation of the Java code into Python:

```Python
class SearchTextDialog:
    def __init__(self):
        self.plugin = None
        self.tool = None
        self.next_button = None
        self.previous_button = None
        self.all_button = None
        self.value_field = None
        self.case_sensitive_cb = None
        self.search_selection_cb = None
        self.history = []
        self.is_busy = False

    def close(self):
        super().close()

    def show(self, component_provider):
        clear_status_text()
        value_field.request_focus()
        value_field.select_all()
        tool.show_dialog(self, component_provider)
        is_busy = False
        update_search_buttons_enablement()

    @staticmethod
    def dismiss_callback():
        close()
        cancel_current_task()

    def set_status_text(self, text):
        if SwingUtilities.is_event_dispatch_thread():
            super().set_status_text(text)
        else:
            SwingUtilities.invokeLater(lambda: self.set_message(text))

    def execute_progress_task(self, task, delay):
        super().execute_progress_task(task, delay)

    @staticmethod
    def get_task_monitor_component():
        return super().get_task_monitor_component()

    @staticmethod
    def get_task_scheduler():
        return super().get_task_scheduler()

    def update_search_buttons_enablement(self):
        all_button.set_enabled(not is_busy and search_enabled)
        next_button.set_enabled(not is_busy and search_enabled)
        previous_button.set_enabled(not is_busy and search_enabled)

    def set_has_selection(self, has_selection):
        self.search_selection_cb.set_selected(has_selection)

    @staticmethod
    def get_search_options():
        value = value_field.get_text()
        if all_button.is_selected():
            return SearchOptions(value, case_sensitive_cb.is_selected(), True)
        else:
            return SearchOptions(value, program_database_search_rb.is_selected(),
                                  functions_cb.is_selected(), comments_cb.is_selected(),
                                  labels_cb.is_selected(), mnemonics_cb.is_selected(),
                                  operands_cb.is_selected(), data_mnemonics_cb.is_selected(),
                                  data_operands_cb.is_selected(), case_sensitive_cb.is_selected())

    def validate(self):
        value = value_field.get_text()
        if not value:
            set_status_text("Please enter a pattern to search for.")
            return False
        elif UserSearchUtils.STAR == value:
            set_status_text("Pattern must contain a non-wildcard character.")
            return False

        if all_button.is_selected():
            return True

        if (not comments_cb.is_selected() and not labels_cb.is_selected()
                and not mnemonics_cb.is_selected() and not operands_cb.is_selected()
                and not data_mnemonics_cb.is_selected() and not data_operands_cb.is_selected()):
            set_status_text("Please select an option to search.")
            return False

        return True

    def search_all(self):
        clear_status_text()

        if validate():
            plugin.search_all(get_search_options())
            is_busy = True
            update_search_buttons_enablement()

    @staticmethod
    def task_completed(task):
        super().task_completed(task)
        is_busy = False
        if plugin:
            search_enabled = plugin.get_navigatable() != None
            update_search_buttons_enablement()

    @staticmethod
    def task_cancelled(task):
        super().task_cancelled(task)
        is_busy = False
        if plugin:
            search_enabled = plugin.get_navigatable() != None
            update_search_buttons_enablement()

    def repeat_search(self):
        next_previous(forward)

    def add_to_history(self, input):
        history.remove(input)
        truncate_history_as_needed()
        update_combo()

    @staticmethod
    def match_history(input):
        if not input:
            return None

        for cur in history:
            if cur.startswith(input):
                return cur

        return None

    class AutoCompleteDocument(DefaultStyledDocument):

        def __init__(self, previous_input=None):
            super().__init__()
            self.previous_input = previous_input
            self.automated = False

        @staticmethod
        def insert_string(offs, str, a):
            super().insert_string(offs, str, a)
            if automated:
                automated = False
            else:
                input = value_field.get_text()
                # If the text has changed
                if not input == previous_input:
                    previous_input = input
                    match = SearchTextDialog.match_history(input)
                    if match and len(match) > input.length():
                        automated = True
                        value_field.set_text(match)
                        value_field.select_start(input.length())
                        value_field.select_end(len(match))
```

Please note that this is a direct translation of the Java code into Python, without any modifications or optimizations.