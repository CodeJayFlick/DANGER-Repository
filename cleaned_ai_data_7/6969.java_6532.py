class AnonymousVariableAccessDR:
    def __init__(self, line, token):
        super().__init__(line, token)

    def accumulate_matches(self, dt, field_name, results):
        # This class is backed by a ClangFieldToken.  That class' s data type is the composite 
        # that contains the field being accessed.
        
        field = self.source_token
        composite_type = field.data_type
        field_dt = DecompilerReference.get_field_data_type(field)

        matches_composite = dt == composite_type
        matches_field = dt == field_dt
        no_match = not (matches_composite or matches_field)
        if no_match:
            return

        if field_name is None:
            # case 2; no field name to check
            if matches_field:
                results.append(self.create_reference())
            return

        # case 1; check the field name and the composite type
        if matches_composite and field.text == field_name:
            results.append(DataTypeReference(composite_type, field_name, self.function(), self.address(), self.context()))
