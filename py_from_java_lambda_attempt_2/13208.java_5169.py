Here is the translation of the Java code into equivalent Python:

```Python
class InjectPayloadJavaParameters:
    def __init__(self, name: str, source_name: str, language: object, uniq_base: int):
        self.name = name
        self.source_name = source_name
        self.no_params = []
        self.analysis_state_recoverable = True
        self.constant_space = None
        self.param_space_id = 0
        self.lva_id = 0

    def get_name(self) -> str:
        return self.name

    def get_type(self) -> int:
        # Not used in this translation, so returning a default value.
        return 1

    def get_source(self) -> str:
        return self.source_name

    def get_param_shift(self) -> int:
        return 0

    def get_input(self) -> list:
        return self.no_params

    def get_output(self) -> list:
        return self.no_params

    def is_error_placeholder(self) -> bool:
        return False

    def inject(self, context: object, emit: object):
        # Not used in this translation, so doing nothing.
        pass

    def get_pcode(self, program: object, con: object) -> list:
        if not self.analysis_state_recoverable:
            return []

        try:
            analysis_state = ClassFileAnalysisState.get_state(program)
        except Exception as e:
            Msg.error(self, str(e), e)
            self.analysis_state_recoverable = False
            return []

        class_file = analysis_state.get_class_file()
        method_info = analysis_state.get_method_info(con.base_addr)

        if method_info is None:
            return []

        descriptor_index = method_info.descriptor_index
        descriptor_info = ConstantPoolUtf8Info(class_file.constant_pool[descriptor_index])
        descriptor = descriptor_info.string

        param_categories = []
        if not method_info.is_static():
            param_categories.append(JavaComputationalCategory.CAT_1)

        param_categories.extend(DescriptorDecoder.get_parameter_categories(descriptor))

        num_ops = len(param_categories)
        res_ops = [PcodeOp(con.base_addr, 0, PcodeOp.COPY)]
        seq_num = 1

        copy = PcodeOp(con.base_addr, seq_num, PcodeOp.COPY)
        copy.input[0] = zero
        copy.output = LVA
        res_ops.append(copy)

        temp_location = None
        increment = None

        for cat in param_categories:
            if cat == JavaComputationalCategory.CAT_1:
                temp_location = temp4
                increment = four
            else:
                temp_location = temp8
                increment = eight

            load = PcodeOp(con.base_addr, seq_num, PcodeOp.LOAD)
            load.input[0] = Varnode(constant_space.get_address(param_space_id), 4)
            load.input[1] = LVA
            load.output = temp_location
            res_ops.append(load)

            store = PcodeOp(con.base_addr, seq_num, PcodeOp.STORE)
            store.input[0] = Varnode(constant_space.get_address(lva_id), 4)
            store.input[1] = LVA
            store.input[2] = temp_location
            res_ops.append(store)

            add = PcodeOp(con.base_addr, seq_num, PcodeOp.INT_ADD)
            add.input[0] = LVA
            add.input[1] = increment
            add.output = LVA
            res_ops.append(add)

        return res_ops

    def is_fall_thru(self) -> bool:
        return True

    def is_incidental_copy(self) -> bool:
        return False

    def save_xml(self, buffer: str):
        buffer += "<pcode"
        SpecXmlUtils.encode_string_attribute(buffer, "inject", "uponentry")
        SpecXmlUtils.encode_boolean_attribute(buffer, "dynamic", True)
        buffer += "/>\n"

    def restore_xml(self, parser: object, language: object) -> None:
        el = parser.start()
        inject_string = el.attribute("inject")

        if inject_string is None or not inject_string.equals("uponentry"):
            raise XmlParseException("Expecting inject=\"uponentry\" attribute")

        is_dynamic = SpecXmlUtils.decode_boolean(el.attribute("dynamic"))

        if not is_dynamic:
            raise XmlParseException("Expecting dynamic attribute")

        parser.end(el)

    def __eq__(self, obj: object) -> bool:
        return isinstance(obj, InjectPayloadJavaParameters)

    def __hash__(self) -> int:
        return 123474217
```

Please note that this translation is not perfect and some parts might be missing or incorrect.