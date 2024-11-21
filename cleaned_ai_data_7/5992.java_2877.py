class CompilerProjectDataColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Compiler"

    def get_value(self, info, settings, data, services):
        if not isinstance(info, dict) or 'Compiler ID' not in info:
            raise ValueError("Invalid compiler information")
        return info['Compiler ID']

    def get_column_preferred_width(self):
        return 100

    def is_default_column(self):
        return True

    def get_priority(self):
        return 4
