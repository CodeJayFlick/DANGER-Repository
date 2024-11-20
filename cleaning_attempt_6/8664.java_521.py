class DiffApplyTestAdapter:
    def __init__(self):
        self.ignore_all = None
        self.replace_all = None
        self.merge_all = None
        self.settings_panel = None
        self.program_context_apply_cb = None
        self.byte_apply_cb = None
        self.code_unit_apply_cb = None
        self.ref_apply_cb = None
        self.plate_comment_apply_cb = None
        self.pre_comment_apply_cb = None
        self.eol_comment_apply_cb = None
        self.repeatable_comment_apply_cb = None
        self.post_comment_apply_cb = None
        self.label_apply_cb = None
        self.function_apply_cb = None
        self.bookmark_apply_cb = None
        self.properties_apply_cb = None
        self.function_tag_apply_cb = None

    def ignore(self, comboBox):
        model = comboBox.model()
        for i in range(model.size()):
            if str(model.get(i)) == "Ignore":
                comboBox.setCurrentIndex(i)
                break
        self.is_ignore(comboBox)

    def replace(self, comboBox):
        model = comboBox.model()
        for i in range(model.size()):
            if str(model.get(i)) == "Replace":
                comboBox.setCurrentIndex(i)
                break
        self.is_replace(comboBox)

    def merge(self, comboBox):
        model = comboBox.model()
        for i in range(model.size()):
            if str(model.get(i)) == "Merge":
                comboBox.setCurrentIndex(i)
                break
        self.is_merge(comboBox)

    def is_ignore(self, comboBox):
        assertEqual(str(comboBox.currentText()), "Ignore")

    def is_replace(self, comboBox):
        assertEqual(str(comboBox.currentText()), "Replace")

    def is_merge(self, comboBox):
        assertEqual(str(comboBox.currentText()), "Merge")

    def apply(self):
        self.apply_diffs()
        time.sleep(1)
        while getWindow("Apply Differences") != None:
            pass
        time.sleep(1)

    def ignore_and_next(self):
        self.ignore_diffs()
        time.sleep(1)
        while getWindow("Ignore Differences") != None:
            pass
        time.sleep(1)

    def show_apply_settings(self):
        self.diff_apply_settings()
        assertTrue(is_provider_shown(tool.get_tool_frame(), "Diff Apply Settings"))
        self.settings_panel = find_component_by_name(tool.get_tool_frame(), "Diff Apply Settings Panel")
        assertNotNone(self.settings_panel)
        get_apply_settings_actions()
        get_apply_settings_comboboxes()

    def check_diff_selection(self, addr_set):
        expected_selection = ProgramSelection(addr_set)
        current_selection = cb.current_selection
        missing_from_selection = expected_selection.subtract(current_selection)
        unexpectedly_selected = current_selection.subtract(expected_selection)
        if not missing_from_selection.is_empty():
            print("Selection expected the following addresses but they are missing: " + str(missing_from_selection))
        if not unexpectedly_selected.is_empty():
            print("Selection unexpectedly contains the following addresses: " + str(unexpectedly_selected))
        assertEqual(expected_selection, current_selection)

    def check_program_selection(self, addr_set):
        assertEqual(ProgramSelection(addr_set), cb.current_selection)
