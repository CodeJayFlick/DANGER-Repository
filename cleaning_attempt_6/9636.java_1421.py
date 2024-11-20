class FilterOptions:
    CONTAINS_ICON = None  # Replace with actual icon loading logic in Python
    STARTS_WITH_ICON = None  # Replace with actual icon loading logic in Python
    EXACT_MATCH_ICON = None  # Replace with actual icon loading logic in Python
    REG_EX_ICON = None  # Replace with actual icon loading logic in Python
    NOT_ICON = None  # Replace with actual icon loading logic in Python

    DELIMITER_NAME_MAP = {}

    def __init__(self, text_filter_strategy=None, allow_globbing=False,
                 case_sensitive=True, inverted=False, multi_term=False,
                 delimiter_character=',', eval_mode='AND'):
        if not isinstance(text_filter_strategy, str):
            raise ValueError("TextFilterStrategy cannot be null")
        
        self.text_filter_strategy = text_filter_strategy
        self.allow_globbing = allow_globbing
        self.case_sensitive = case_sensitive
        self.inverted = inverted
        self.multi_term = multi_term
        self.delimiting_character = delimiter_character
        self.eval_mode = eval_mode

    @staticmethod
    def restore_from_xml(element):
        filter_type_name = element.get('FILTER_TYPE')
        text_filter_strategy = FilterOptions.get_text_filter_strategy(filter_type_name)
        
        glob_value = element.get('GLOBBING', 'True')
        allow_globbing = bool(glob_value)

        case_sensitive_str = element.get('CASE_SENSITIVE', 'True')
        case_sensitive = bool(case_sensitive_str)

        inverted_str = element.get('INVERTED', 'False')
        inverted = bool(inverted_str)

        multiterm_str = element.get('MULTITERM', 'False')
        multi_term = bool(multiterm_str)

        delimiter_character_str = element.get('TERM_DELIMITER') or f"'{FilterOptions.DEFAULT_DELIMITER}'"
        
        and_mode_str = element.get('AND_EVAL_MODE', 'True')
        eval_mode = 'AND' if and_mode_str else 'OR'

        return FilterOptions(text_filter_strategy, allow_globbing,
                              case_sensitive, inverted, multi_term,
                              delimiter_character_str[1:-1], eval_mode)

    @staticmethod
    def get_text_filter_strategy(filter_type_name):
        if filter_type_name is None:
            return 'CONTAINS'
        
        # Replace with actual logic to map string to TextFilterStrategy in Python
        pass

    def to_xml(self):
        xml_element = Element('Filter_Options')
        xml_element.set('FILTER_TYPE', self.text_filter_strategy)
        xml_element.set('GLOBBING', str(self.allow_globbing))
        xml_element.set('CASE_SENSITIVE', str(self.case_sensitive))
        xml_element.set('INVERTED', str(self.inverted))

        xml_element.set('MULTITERM', str(self.multi_term))
        xml_element.set('TERM_DELIMITER', f"'{self.delimiting_character}'")

        xml_element.set('AND_EVAL_MODE', 'True' if self.eval_mode == 'AND else 'False')

        return xml_element

    def is_case_sensitive(self):
        return self.case_sensitive

    def is_globbing_allowed(self):
        return self.allow_globbing

    def is_inverted(self):
        return self.inverted

    def get_text_filter_strategy(self):
        return self.text_filter_strategy

    def is_multiterm(self):
        return self.multi_term

    def get_delimiting_character(self):
        return self.delimiting_character

    def get_multiterm_evaluation_mode(self):
        return self.eval_mode

    @staticmethod
    def get_icon(filter_strategy):
        # Replace with actual logic to map TextFilterStrategy to Icon in Python
        pass

    def get_filter_state_icon(self):
        icon = FilterOptions.get_icon(self.text_filter_strategy)
        
        if self.inverted:
            width, height = icon.get_size()
            not_width, not_height = NOT_ICON.get_size()
            icon = MultiIcon(icon, TranslateIcon(NOT_ICON, (width - not_width) / 2, (height - not_height) / 2))
        
        return icon

    def get_filter_description(self):
        buf = StringBuffer('<html>')
        buf.append('<b>Filter Settings:</b><br/>')
        buf.append('<table>')
        
        # Replace with actual logic to generate HTML table in Python
        pass
        
        return buf.toString()
