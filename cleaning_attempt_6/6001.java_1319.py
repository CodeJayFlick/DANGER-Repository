class ProcessorProjectDataColumn:
    def __init__(self):
        pass

    def get_column_name(self):
        return "Processor"

    def get_value(self, info: dict, settings: dict, data: dict) -> str:
        if 'meta_data' in info and 'processor' in info['meta_data']:
            return info['meta_data']['processor']
        else:
            raise ValueError("Invalid metadata")

    @property
    def column_preferred_width(self):
        return 100

    @property
    def is_default_column(self) -> bool:
        return True

    @property
    def priority(self) -> int:
        return 1
