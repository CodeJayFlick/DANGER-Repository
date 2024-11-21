class MDMangVS2015:
    def demangle(self, mangled_in: str, error_on_remaining_chars: bool) -> 'MDParsableItem':
        returned_item = super().demangle(mangled_in, error_on_remaining_chars)
        
        if isinstance(returned_item, MDObjectBracket):
            return returned_item
        elif isinstance(returned_item, MDObjectReserved):
            raise MDException("Invalid mangled symbol.")
        else:
            return returned_item

    def insert(self, builder: 'StringBuilder', mdstring: 'MDString'):
        self.insert_string(builder, mdstring.name)

    def insert(self, builder: 'StringBuilder', qualification: 'MDQualification'):
        qualification.insert_vs_all(builder)

    @property
    def empty_first_arg_comma(self) -> bool:
        return True

    @property
    def template_backref_comma(self) -> bool:
        return False

    def insert_managed_properties_suffix(self, builder: 'StringBuilder', cv_mod: 'MDCVMod'):
        pass  # Do nothing

    # TODO: Look into this further. We may no longer need to have this specialization,
    # but it be that I just haven't implemented it yet too...
    # @property
    # def parse_embedded_object_suffix(self) -> None:
    #     pass  # Do nothing

    def insert_cli_array_ref_suffix(self, builder: 'StringBuilder', ref_builder: 'StringBuilder'):
        builder.length = 0
        self.insert_string(builder, str(ref_builder))

    def parse_fragment_name(self, fn: 'MDFragmentName') -> str:
        return fn.parse_fragment_name_vs2_all()

    def append_array_notation(self, builder: 'StringBuilder', array_basic_type: 'MDArrayBasicType'):
        array_basic_type.append_array_notation(builder)

    @property
    def allow_md_type_info_parser_default(self) -> bool:
        return True

    @property
    def process_qual_c_as_special_fragment(self) -> bool:
        return False

    def get_embedded_object(self, obj: 'MDObjectCPP') -> 'MDObjectCPP':
        return obj.get_embedded_object()

    def process_hashed_object(self, obj: 'MDObjectCPP'):
        obj.process_hashed_object_msvc()
