class ViewStringsContext:
    def __init__(self, provider: 'ViewStringsProvider', strings_table):
        self.provider = provider
        self.strings_table = strings_table

    @property
    def strings_table(self) -> object:
        return self.strings_table

    def get_count(self) -> int:
        return self.provider.get_selected_row_count()

    def get_program(self) -> 'Program':
        return self.provider.get_program()

    def get_data_location_list(self) -> list['ProgramLocation']:
        return self.provider.get_selected_data_locations(None)

    def get_filtered_data_location_list(self, filter: callable) -> list['ProgramLocation']:
        return self.provider.get_selected_data_locations(filter)
