Here is the translation of the Java code into Python:

```Python
class CodeUnitTableCellData:
    def __init__(self, location: 'ProgramLocation', code_unit_format: 'CodeUnitFormat',
                 code_unit_offset: int, code_unit_count: int):
        if not isinstance(location, ProgramLocation):
            raise Exception("ProgramLocation cannot be null")
        
        self.program = location.get_program()
        if not isinstance(code_unit_format, CodeUnitFormat):
            raise Exception("CodeUnitFormat cannot be null")

        self.formatter = code_unit_format
        self.code_unit_offset = code_unit_offset
        self.code_unit_count = code_unit_count
        self.address = location.get_byte_address()

    def __str__(self) -> str:
        return self.display_string

    def compare_to(self, data: 'CodeUnitTableCellData') -> int:
        return self.display_string.casefold().compare(data.display_string.casefold())

    @property
    def display_string(self) -> str:
        if not isinstance(self._display_string, str):
            self._display_string = create_display_string(False)
        return self._display_string

    @property
    def html_display_string(self) -> str:
        if not isinstance(self._html_display_string, str):
            self._html_display_string = "<html><pre>" + create_display_string(True) + "</pre></html>"
        return self._html_display_string

    @property
    def display_strings(self) -> list[str]:
        return get_display_lines(False)

    @property
    def is_offcut(self) -> bool:
        return self._is_offcut

    def data_path(self, data: 'Data') -> str:
        path = data.get_component_path_name()
        dot_index = path.find(".")
        if dot_index != -1:
            path = path[dot_index + 1:]
        
        parent = data.get_parent()
        parent_type = parent.get_data_type()

        separator = "."
        if isinstance(parent_type, Array):
            separator = ""

        return " (" + parent_type.name + separator + path + ")"

    def code_unit_containing(self, addr: 'Address') -> 'CodeUnit':
        listing = self.program.get_listing()
        cu = listing.get_code_unit_at(addr)
        if cu is None:
            cu = listing.get_code_unit_containing(addr)
            if isinstance(cu, Data):
                data = cu
                return data.get_primitive_at(int(addr.subtract(data.min_address())))
        
        return cu

    def code_unit_before(self, cu: 'CodeUnit') -> 'CodeUnit':
        if cu is not None:
            try:
                return self.code_unit_containing(cu.min_address().subtract_no_wrap(1))
            except AddressOverflowException:
                pass
        
        return None

    def code_unit_after(self, cu: 'CodeUnit') -> 'CodeUnit':
        if cu is not None:
            try:
                return self.code_unit_containing(cu.max_address().add_no_wrap(1))
            except AddressOverflowException:
                pass
        
        return None

    def create_display_string(self, html_friendly: bool) -> str:
        lines = get_display_lines(html_friendly)
        buffy = StringBuilder()
        for i in range(len(lines)):
            string = lines[i]
            buffy.append(string)
            if i < len(lines) - 1:
                buffy.append("\n")
        
        return buffy.toString()

    def display_lines(self, html_friendly: bool) -> list[str]:
        lines = []

        if self.address.is_external_address():
            return lines
        
        code_unit_start = self.code_unit_offset
        code_unit_end = code_unit_start + self.code_unit_count - 1

        containing_code_unit = self.code_unit_containing(self.address)
        code_unit = containing_code_unit
        code_unit_index = 0
        count = 0
        if code_unit_start <= 0 and code_unit_end >= 0:
            lines.append(create_display_string(code_unit, self.formatter, html_friendly))
            count += 1
        
        while count < self.code_unit_count:
            # Get next code unit
            if code_unit_index <= 0:
                if code_unit_index <= code_unit_start:
                    # switch to the forward direction
                    code_unit = containing_code_unit
                    code_unit_index = 0
                else:
                    # check previous code unit
                    code_unit = self.code_unit_before(code_unit)
                    --code_unit_index
            
            if code_unit_index >= 0:
                # check next code unit
                code_unit = self.code_unit_after(code_unit)
                ++code_unit_index
        
            # Generate code-unit representation if needed
            if code_unit_index >= code_unit_start and code_unit_index <= code_unit_end:
                display = create_display_string(code_unit, self.formatter, html_friendly)
                if code_unit_index < 0:
                    lines.insert(0, display)
                else:
                    lines.append(display)
                count += 1
        
        return lines

    def create_codeunit_representation(self, cu: 'CodeUnit', cu_format: 'CodeUnitFormat') -> str:
        representation = None
        if isinstance(cu, Data):
            representation = cu_format.get_representation_string(cu)
        
        if representation is None or len(representation) == 0:
            representation = "??"
        
        if self.formatter.html_friendly:
            if len(representation) > MAX_LINE_LENGTH:
                representation = representation[:MAX_LINE_LENGTH]
            
            representation = HTMLUtilities.friendly_encode_html(representation)
        
        return representation

    def create_display_string(self, cu: 'CodeUnit', cu_format: 'CodeUnitFormat', html_friendly: bool) -> str:
        if not isinstance(cu, CodeUnit):
            raise Exception("Invalid code unit")
        
        representation = self.create_codeunit_representation(cu, cu_format)
        return representation

    MAX_LINE_LENGTH = 500
```

Please note that Python does not support Java's `@Override` annotation.