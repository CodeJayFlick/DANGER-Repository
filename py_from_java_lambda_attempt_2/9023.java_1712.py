Here is the translation of the Java code into Python:

```Python
class VTMatchTableModel:
    TITLE = "VTMatch Table Model"

    def __init__(self, controller):
        super().__init__(TITLE, controller)

    def create_table_column_descriptor(self):
        descriptor = {}
        
        # Add visible columns
        descriptor['Tag'] = TagTableColumn()
        descriptor['Session Number'] = SessionNumberTableColumn()
        descriptor['Status'] = StatusTableColumn(True)
        descriptor['Match Type'] = MatchTypeTableColumn()
        descriptor['Score'] = ScoreTableColumn()
        descriptor['Confidence Score'] = ConfidenceScoreTableColumn()
        descriptor['Implied Match Count'] = ImpliedMatchCountColumn()
        descriptor['Related Match Count'] = RelatedMatchCountColumn()
        descriptor['Multiple Source Labels'] = MultipleSourceLabelsTableColumn()
        descriptor['Source Namespace'] = SourceNamespaceTableColumn()
        descriptor['Source Label'] = SourceLabelTableColumn()
        descriptor['Destination Address'] = DestinationAddressTableColumn(True)
        descriptor['Multiple Destination Labels'] = MultipleDestinationLabelsTableColumn()
        descriptor['Destination Namespace'] = DestinationNamespaceTableColumn()
        descriptor['Destination Label'] = DestinationLabelTableColumn()
        descriptor['Algorithm'] = AlgorithmTableColumn()

        return descriptor

    def is_cell_editable(self, row_index, column_index):
        if column_index == self.get_column_index(TagTableColumn):
            return True
        else:
            return super().is_cell_editable(row_index, column_index)

    def get_address(self, row):
        match = self.get_row_object(row)
        association = match.get_association()
        return association.get_source_address()

    def do_load(self, accumulator, monitor):
        if not hasattr(self, 'session'):
            raise AttributeError("VTMatchTableModel must have a session attribute")
        
        monitor.initialize(len(self.session.match_sets))
        
        for i, match_set in enumerate(self.session.match_sets):
            monitor.check_cancelled()
            matches = list(match_set.matches)
            for j, match in enumerate(matches):
                monitor.increment_progress(1)
                accumulator.add(match)

    def get_match_count(self):
        count = 0
        for match_set in self.session.match_sets:
            count += len(list(match_set.matches))
        return count

    def create_sort_comparator(self, column_index):
        if column_index == self.get_column_index(DestinationAddressTableColumn):
            return DestinationAddressComparator()
        elif column_index == self.get_column_index(SourceAddressTableColumn):
            return SourceAddressComparator()
        # Add more conditions for other columns
        else:
            return super().create_sort_comparator(column_index)
```

Please note that Python does not have direct equivalent of Java's `package`, so the code is written as a single class. Also, some classes and methods are missing in this translation because they were not provided in the original Java code.