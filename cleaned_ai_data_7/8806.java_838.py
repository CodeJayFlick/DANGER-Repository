class ProgramCorrelatorInfoImpl:
    def __init__(self, match_set):
        self.match_set_db = match_set
        self.correlator_class_name = None
        self.name = None
        self.source_address_set = None
        self.destination_address_set = None
        self.options = None

    @property
    def correlator_class_name(self):
        if not self.correlator_class_name:
            self.correlator_class_name = self.match_set_db.get_program_correlator_class_name()
        return self.correlator_class_name

    @property
    def name(self):
        if not self.name:
            self.name = self.match_set_db.get_program_correlator_name()
        return self.name

    @property
    def source_address_set(self):
        if not self.source_address_set:
            try:
                self.source_address_set = self.match_set_db.get_source_address_set()
            except Exception as e:
                print(f"Error retrieving program correlator info: {self.correlator_class_name}")
                raise e
        return self.source_address_set

    @property
    def destination_address_set(self):
        if not self.destination_address_set:
            try:
                self.destination_address_set = self.match_set_db.get_destination_address_set()
            except Exception as e:
                print(f"Error retrieving program correlator info: {self.correlator_class_name}")
                raise e
        return self.destination_address_set

    @property
    def options(self):
        if not self.options:
            self.options = self.match_set_db.get_options()
        return self.options
