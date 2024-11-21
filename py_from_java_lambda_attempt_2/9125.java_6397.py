Here is the translation of the Java code into Python:

```Python
class VtTestEnv:
    def __init__(self):
        self.session = None
        self.controller = None
        self.plugin = None
        self.source_program = None
        self.destination_program = None
        self.match_table_provider = None

    def create_session(self, source_program_name: str, destination_program_name: str) -> VTSessionDB:
        if not self.session:
            raise AssertionError("You must create the session before you can add items")
        
        correlator = factory.create_correlator(get_tool(), 
                                               self.source_program.get_memory(),
                                               self.destination_program.get_memory())
        
        id = self.session.start_transaction("Correlate")
        correlator.correlate(self.session, TaskMonitor.DUMMY)
        self.session.end_transaction(id, True)

    def add_to_session(self) -> VTSessionDB:
        if not self.session:
            raise AssertionError("You must create the session before you can add items")

        return self.create_and_open_vt_session()

    def get_vt_controller(self):
        return self.controller

    def get_session(self):
        return self.session

    def get_source_program(self):
        return self.source_program

    def get_destination_program(self):
        return self.destination_program

    def select_matches_in_match_table(self, rows: int) -> List[VTMatch]:
        table = match_table_provider.get_component()
        model = table.model
        matches = []

        for row in rows:
            matches.append(model.row_object(row))

        return matches

    def get_selected_match_row(self):
        table = self.match_table_provider.get_component()
        model = table.model
        selected_row = None

        run_swing(lambda: selected_row = table.selected_row)

        return selected_row

    def get_selected_match(self) -> VTMatch:
        table = match_table_provider.get_component()
        model = table.model
        selected_row = self.get_selected_match_row()

        if not selected_row:
            raise AssertionError("No row is selected")

        return model.row_object(selected_row)
```

Note: The above Python code assumes that you have a `VTSessionDB`, `VTProgramCorrelatorFactory`, `TaskMonitor`, and other classes defined elsewhere in your project.