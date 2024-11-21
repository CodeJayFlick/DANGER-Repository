import collections

class VTMatchDestinationTableModel:
    TITLE = "VTMatch Destination Table Model"

    def __init__(self, vt_controller):
        super().__init__(TITLE, vt_controller)

    def create_table_column_descriptor(self):
        descriptor = {}
        # Add columns here...
        return descriptor

    def get_address(self, row):
        match = self.get_row_object(row)
        association = match["association"]
        return association["source_address"]

    def do_load(self, accumulator, monitor):
        if self.address is not None:
            associations = session.association_manager.get_related_associations_by_destination_address(self.address)
            for vt_association in associations:
                matches = session.matches(vt_association)
                accumulator.update(matches)
                monitor.check_canceled()
                monitor.increment_progress(1)

    def create_sort_comparator(self, column_index):
        # Unusual Code Alert!...
        if column_index == self.get_column_index(SourceAddressTableColumn()):
            return SourceAddressComparator()

        return super().create_sort_comparator(column_index)


class VTMatch:
    pass


class Session:
    association_manager = None
    matches = None

# Other classes...

if __name__ == "__main__":
    vt_controller = None  # Initialize the controller...
    model = VTMatchDestinationTableModel(vt_controller)
