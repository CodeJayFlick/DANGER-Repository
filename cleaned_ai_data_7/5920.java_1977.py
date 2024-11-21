class CodeUnitTableColumn:
    def __init__(self):
        self.CODE_UNIT_COUNT = 'Code Unit Count'
        self.CODE_UNIT_OFFSET = 'Code Unit Offset'
        self.settings_defs = [self.CODE_UNIT_COUNT, self.CODE_UNIT_OFFSET]
        self.code_unit_format = None

    def get_column_name(self):
        return "Code Unit"

    def get_column_display_name(self, settings):
        name = self.get_column_name()
        preview_cnt = 1
        offset = '0'
        if not isinstance(settings, dict) or 'code_unit_count' in settings:
            preview_cnt = int(settings['code_unit_count'])
        if not isinstance(settings, dict) or 'code_unit_offset' in settings:
            offset = str(settings.get('code_unit_offset', 0))
        if preview_cnt != 1:
            name += f" [{preview_cnt}]"
        if offset != '0':
            name += f" {offset}"
        return name

    def get_value(self, row_object, settings):
        loc = row_object
        code_unit_format = self.get_code_unit_format()
        count = int(settings['code_unit_count'])
        offset = int(settings.get('code_unit_offset', 0))
        return {'location': loc, 'format': code_unit_format, 'count': count, 'offset': offset}

    def get_code_unit_format(self):
        if not self.code_unit_format:
            self.code_unit_format = BrowserCodeUnitFormat()
        return self.code_unit_format

    def get_program_location(self, row_object, settings):
        return row_object

    def get_column_renderer(self):
        return CodeUnitTableCellRenderer()

    def get_settings_definitions(self):
        return self.settings_defs

    def get_max_lines(self, settings):
        return int(settings['code_unit_count'])
