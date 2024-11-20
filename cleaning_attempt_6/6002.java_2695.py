class ReferencesFromTableModel:
    def __init__(self, refs: list[Reference], sp: ServiceProvider, program: Program):
        self.refs = [IncomingReferenceEndpoint(r, ReferenceUtils.is_offcut(program, r.get_to_address())) for r in refs]
        super().__init__("References", sp, program)

    @property
    def column_names(self) -> tuple:
        return ("Ref Type", )

    def get_row_object(self, row: int):
        return self.refs[row]

class ReferenceTypeTableColumn:
    def __init__(self):
        pass

    def get_value(self, row_object: IncomingReferenceEndpoint, settings: Settings, program: Program, sp: ServiceProvider) -> IncomingReferenceEndpoint:
        return row_object

    @property
    def column_name(self) -> str:
        return "Ref Type"

class ReferenceTypeTableCellRenderer:
    OFFCUT_STRING = "&lt;&lt; OFFCUT &gt;&gt;"
    
    def __init__(self):
        self.set_html_rendering_enabled(True)

    def get_table_cell_renderer_component(self, data: GTableCellRenderingData) -> Component:
        label = super().get_table_cell_renderer_component(data)
        
        row_object = data.get_value()
        text = str(row_object)
        if row_object.is_offcut():
            text += self.OFFCUT_STRING
        label.set_text(text)

        return label

    def as_string(self, row_object: IncomingReferenceEndpoint) -> str:
        ref_type = row_object.get_reference_type().get_name()
        if row_object.is_offcut():
            ref_type = f"<html>{HTMLUtilities.color_string(Color.RED, ref_type + self.OFFCUT_STRING)}"
        return ref_type

    def get_filter_string(self, t: IncomingReferenceEndpoint, settings: Settings) -> str:
        html_string = self.as_string(t)
        # TODO verify this returns '<' instead of entity refs
        return HTMLUtilities.from_html(html_string)

class IncomingReferenceEndpoint:
    def __init__(self, reference: Reference, is_offcut: bool):
        self.reference = reference
        self.is_offcut = is_offcut

    @property
    def get_reference_type(self) -> RefType:
        # This method should return the ref type of the given reference.
        pass

class Program:
    def __init__(self):
        pass

class ServiceProvider:
    def __init__(self):
        pass

class Reference:
    def __init__(self):
        pass

class RefType:
    def __init__(self, name: str):
        self.name = name
