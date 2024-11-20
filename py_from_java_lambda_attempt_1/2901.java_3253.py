Here is the translation of the given Java code into Python:

```Python
class EntropyFieldFactory:
    FIELD_NAME = "Entropy"

    def __init__(self):
        super().__init__(FIELD_NAME)

    @classmethod
    def get_field(cls, proxy_obj: object, var_width: int) -> 'ListingField':
        if not cls.enabled:
            return None

        obj = proxy_obj.get_object()
        if not (cls.enabled and isinstance(obj, CodeUnit)):
            return None

        cu = obj
        bytes_ = bytearray(256)
        entropy = 0.0
        try:
            num_bytes = cu.get_program().get_memory().get_bytes(cu.get_address(), bytes_)
            if num_bytes < len(bytes_):
                return None
            entropy = cls._calc_entropy(bytes_, 0, num_bytes)
            hsbvals = Color.RGBtoHSB(255, 0, 0, None)
            color = Color.HSBtoRGB(hsbvals[0], hsbvals[1], (hsbvals[1] * (entropy / 8.0)))
        except MemoryAccessException:
            return None

        str_ = f"{int((entropy / 8.0) * 100)}"
        text = AttributedString(str_, color, cls.get_metrics())
        field_element = TextFieldElement(text, 0, 0)
        return ListingTextField.create_single_line_text_field(cls, proxy_obj, field_element,
                                                                 startX + var_width, width, hl_provider)

    @classmethod
    def _calc_entropy(cls, bytes_: bytearray, start: int, len_: int) -> float:
        sum_ = 0.0

        count_array = [0] * 256

        for i in range(start, (start + len_)):
            count_array[bytes_[i] & 0xff] += 1

        for count in count_array:
            if count == 0:
                continue
            p_x = count / len_
            sum_ -= p_x * math.log(p_x) * 1.0 / math.log(2)

        return sum_

    @classmethod
    def get_program_location(cls, row: int, col: int, bf: 'ListingField') -> ProgramLocation:
        proxy_obj = bf.get_proxy()
        obj = proxy_obj.get_object()

        if isinstance(obj, CodeUnit):
            layout_model = proxy_obj.get_listing_layout_model()
            program = layout_model.get_program()
            return EntropyFieldLocation(program, (obj).get_address(), col)
        else:
            return None

    @classmethod
    def get_field_location(cls, bf: 'ListingField', index: BigInteger, field_num: int,
                            program_loc: ProgramLocation) -> FieldLocation:
        if isinstance(program_loc, EntropyFieldLocation):
            return FieldLocation(index, field_num, 0, (program_loc).get_char_offset())
        else:
            return None

    @classmethod
    def accepts_type(cls, category: int, proxy_object_class: Class) -> bool:
        return category == FieldFormatModel.INSTRUCTION_OR_DATA

    @classmethod
    def new_instance(cls, my_model: 'FieldFormatModel', my_hl_provider: HighlightProvider,
                     display_options: ToolOptions, field_options: ToolOptions):
        return cls(my_model, my_hl_provider, display_options, field_options)
```

Please note that Python does not support exact equivalent of Java's `@Override` annotation. Also, the code assumes you have a class called `ListingField`, and classes like `Color`, `AttributedString`, etc., which are part of Java's standard library but do not exist in Python.