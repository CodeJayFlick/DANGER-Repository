class FilterOptionsEditorDialog:
    def __init__(self, filter_options):
        self.filter_options = filter_options
        self.result_filter_options = None

        main_panel = create_main_panel()
        add_work_panel(main_panel)

        filter_strategy_panel.set_filter_strategy(filter_options.text_filter_strategy)
        multi_term_panel.set_eval_mode(filter_options.multiterm_evaluation_mode)
        multi_term_panel.set_delimiter(filter_options.delimiting_character)

        updated_enablement_for_non_regular_expression_options(
            filter_strategy_panel.get_filter_strategy() != TextFilterStrategy.REGULAR_EXPRESSION
        )

        multi_term_panel.set_multiterm_enabled(filter_options.is_multiterm())

    def ok_callback(self):
        self.result_filter_options = FilterOptions(
            filter_strategy_panel.get_filter_strategy(),
            boolean_panel.is_globbing(),
            boolean_panel.is_case_sensitive(),
            invert_panel.is_inverted,
            multi_term_panel.is_multiterm_enabled(),
            multi_term_panel.get_delimiter(),
            multi_term_panel.get_eval_mode()
        )
        close()

    def get_result_filter_options(self):
        return self.result_filter_options

class FilterStrategyPanel:
    def __init__(self):
        create_panel()

    def set_filter_strategy(self, filter_strategy):
        self.filter_strategy = filter_strategy
        updated_enablement_for_non_regular_expression_options(
            filter_strategy != TextFilterStrategy.REGULAR_EXPRESSION
        )

    def get_filter_strategy(self):
        return self.filter_strategy

class BooleanPanel:
    def __init__(self):
        create_panel()

    def is_case_sensitive(self):
        return case_sensitive_checkbox.isSelected()

    def is_globbing(self):
        return globbing_checkbox.isSelected()

    def set_case_sensitive(self, val):
        case_sensitive_checkbox.setSelected(val)

    def set_globbing(self, val):
        globbing_checkbox.setSelected(val)

class InvertPanel:
    def __init__(self):
        create_panel()

    def is_inverted(self):
        return invert_checkbox.isSelected()

class MultiTermPanel:
    def __init__(self):
        super().__init__()
        enable_checkbox = GCheckBox("Enable Multi-Term Filtering", True)
        title_component = enable_checkbox
        set_title_component(title_component)

        create_panel()

    def get_eval_mode(self):
        return self.eval_mode

    def set_eval_mode(self, eval_mode):
        self.eval_mode = eval_mode
        for rb in mode_buttons:
            if rb.getText() == eval_mode.name():
                rb.setSelected(True)
                break

    def is_multiterm_enabled(self):
        return enable_checkbox.isSelected()

    def get_delimiter(self):
        return delimiter_character_cb.getSelectedItem().toString().charAt(0)

class DelimiterListCellRenderer:
    def __init__(self):
        set_html_rendering_enabled(True)

    def get_item_text(self, value):
        char0 = value.length() > 0 and value.charAt(0) or ' '
        delimiter_name = FilterOptions.DELIMITER_NAME_MAP.getOrDefault(char0, "<i>Unrecognized</i>")
        return f"<html><font face='monospace'>{char0} &nbsp;&nbsp; <i>{delimiter_name}</i>"
