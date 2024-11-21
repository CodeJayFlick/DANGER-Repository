class DiffApplySettingsProvider:
    APPLY_FILTER_CHANGED_ACTION = "Apply Filter Changed"
    ICON = None  # Load image from resources
    TITLE = "Diff Apply Settings"

    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__()
        self.set_icon(ICON)
        self.set_title(TITLE)

    def configure(self, apply_filter):
        self.apply_filter = apply_filter

    def add_actions(self):
        self.plugin.get_tool().add_local_action(self,
            SaveApplySettingsAction(self, self.plugin.apply_settings_mgr))
        self.plugin.get_tool().add_local_action(self,
            DiffIgnoreAllAction(self))
        self.plugin.get_tool().add_local_action(self,
            DiffReplaceAllAction(self))
        self.plugin.get_tool().add_local_action(self,
            DiffMergeAllAction(self))

    def create_choices(self):
        choices = []
        program_context_cb = Choice("Program Context", False)
        bytes_cb = Choice("Bytes", False)
        code_units_cb = Choice("Code Units", False)
        refs_cb = Choice("References", False)
        plate_comments_cb = Choice("Plate Comments", True)
        pre_comments_cb = Choice("Pre Comments", True)
        eol_comments_cb = Choice("EOL Comments", True)
        repeatable_comments_cb = Choice("Repeatable Comments", True)
        post_comments_cb = Choice("Post Comments", True)
        symbols_cb = SymbolsChoice()
        bookmarks_cb = Choice("Bookmarks", False)
        properties_cb = Choice("Properties", False)
        functions_cb = Choice("Functions", False)
        function_tags_cb = Choice("Function Tags", True)

        for choice in [program_context_cb, bytes_cb, code_units_cb,
                       refs_cb, plate_comments_cb, pre_comments_cb,
                       eol_comments_cb, repeatable_comments_cb,
                       post_comments_cb, symbols_cb, bookmarks_cb,
                       properties_cb, functions_cb, function_tags_cb]:
            choices.append(choice)

        max_label_width = 0
        max_combo_width = 0

        for choice in choices:
            label_height = choice.label.get_preferred_size().height
            combo_height = choice.apply_cb.get_preferred_size().height
            if label_height > max_label_width:
                max_label_width = label_height
            if combo_height > max_combo_width:
                max_combo_width = combo_height

        for choice in choices:
            choice.label.set_preferred_size((max_label_width, label_height))
            choice.apply_cb.set_preferred_size((max_combo_width, combo_height))

    def create_apply_filter_panel(self):
        self.create_choices()
        panel = VariableHeightPanel(False, 10, 3)
        panel.tooltip_text("<HTML>For each difference type, select whether to ignore, replace or merge.</HTML>")
        for choice in choices:
            panel.add(choice)

        return JScrollPane(panel)

    def adjust_apply_filter(self):
        try:
            self.adjusting = True
            program_context_cb.set_selected_index(apply_program_context)
            bytes_cb.set_selected_index(apply_bytes)
            code_units_cb.set_selected_index(apply_code_units)
            refs_cb.set_selected_index(apply_references)
            plate_comments_cb.set_selected_index(apply_plate_comments)
            pre_comments_cb.set_selected_index(apply_pre_comments)
            eol_comments_cb.set_selected_index(apply_eol_comments)
            repeatable_comments_cb.set_selected_index(apply_repeatable_comments)
            post_comments_cb.set_selected_index(apply_post_comments)
            symbols_cb.set_selected_index(symbols_index)
            bookmarks_cb.set_selected_index(apply_bookmarks)
            properties_cb.set_selected_index(apply_properties)
            functions_cb.set_selected_index(apply_functions)
            function_tags_cb.set_selected_index(apply_function_tags)

        finally:
            self.adjusting = False
            apply_filter_changed()

    def set_pgm_context_enabled(self, enable):
        if not pgm_context_enabled and enable:
            program_context_cb.set_selected_index(0)
        else:
            pgm_context_enabled = enable

    def get_apply_filter(self):
        return ProgramMergeFilter(apply_filter)

    def set_apply_filter(self, apply_filter):
        self.apply_filter = apply_filter
        adjust_apply_filter()

    def has_apply_selection(self):
        if (apply_program_context | apply_bytes | apply_code_units |
            apply_references | apply_plate_comments | apply_pre_comments |
            apply_eol_comments | apply_repeatable_comments | apply_post_comments |
            apply_symbols | apply_bookmarks | apply_properties | apply_functions |
            apply_function_tags) != 0:
            return True
        else:
            return False

    def apply_filter_changed(self):
        if self.adjusting:
            return
        for listener in self.listener_list:
            listener.action_performed(apply_filter_changed_action)

class Choice(JPanel, Comparable[Choice]):
    type = None
    allow_merge = None
    label = None
    apply_cb = None

    def __init__(self, type, allow_merge):
        super().__init__()
        self.type = type
        self.allow_merge = allow_merge
        init()

    def init(self):
        self.apply_cb = GComboBox(allow_merge and DiffApplySettingsOptionManager.MERGE_CHOICE.values() or DiffApplySettingsOptionManager.REPLACE_CHOICE.values())
        self.label = GDLabel(" " + self.type)
        add(self.apply_cb, BorderLayout.EAST)
        add(self.label, BorderLayout.CENTER)

    def set_selected_index(self, index):
        self.apply_cb.set_selected_index(index)

    def get_selected_index(self):
        return self.apply_cb.get_selected_index()

    def add_action_listener(self, listener):
        self.apply_cb.add_action_listener(listener)

    def remove_action_listener(self, listener):
        self.apply_cb.remove_action_listener(listener)

class SymbolsChoice(Choice):
    pass
