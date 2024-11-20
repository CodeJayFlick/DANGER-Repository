Here is your Java code translated into Python:

```Python
class FunctionSignatureMarkupTest:
    def __init__(self):
        pass

    @staticmethod
    def testDiffParamCount_force_signature_and_names_when_same_count_3_to_2():
        use_match("0x00411ab0", "0x00411a90")

        check_signatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
                         "void FUN_00411a90(char * param_1, char * param_2)")

        set_var_args(source_function=True)
        remove_parameter(destination_function=2)

        check_signatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
                         "void FUN_00411a90(char * param_1, char * param_2)")

        apply_options = vt_test_env.get_vt_controller().get_options()
        set_apply_markup_options_to_defaults(apply_options)
        apply_options.set_enum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE)
        apply_options.set_enum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE)
        apply_options.set_enum(INLINE, ReplaceChoices.REPLACE)
        apply_options.set_enum(NO_RETURN, ReplaceChoices.EXCLUDE)
        apply_options.set_enum(FUNCTION_RETURN_TYPE,
                                ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY)
        apply_options.set_enum(VAR_ARGS, ReplaceChoices.REPLACE)
        apply_options.set_enum(PARAMETER_DATA_TYPES,
                                ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY)
        apply_options.set_enum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY)
        apply_options.set_enum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING)

        check_match_status(VTAssociationStatus.AVAILABLE)
        check_function_signature_status(test_match, VTMarkupItemStatus.UNAPPLIED)

        function_signature_markup_items = get_specific_type_of_markup(
            FunctionSignatureMarkupType.class,
            test_match,
            True
        )
        assert_equal(1, len(function_signature_markup_items))
        check_markup_status(function_signature_markup_items, VTMarkupItemStatus.UNAPPLIED)

        apply_function_signature_markup(function_signature_markup_items)
        check_signatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
                         "void FUN_00411a90(char * param_1, char * param_2)")
        check_markup_status(function_signature_markup_items, VTMarkupItemStatus.REPLACED)

    @staticmethod
    def test_diff_replace_signature_only_3_to_2():
        use_match("0x00411ab0", "0x00411a90")

        check_signatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
                         "void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)")

        set_var_args(source_function=True)
        remove_parameter(destination_function=2)

        check_signatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
                         "void FUN_00411a90(char * param_1, char * param_2)")

        apply_options = vt_test_env.get_vt_controller().get_options()
        set_apply_markup_options_to_defaults(apply_options)
        apply_options.set_enum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE)
        apply_options.set_enum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE)
        apply_options.set_enum(INLINE, ReplaceChoices.EXCLUDE)
        apply_options.set_enum(NO_RETURN, ReplaceChoices.EXCLUDE)
        apply_options.set_enum(FUNCTION_RETURN_TYPE,
                                ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY)
        apply_options.set_enum(VAR_ARGS, ReplaceChoices.REPLACE)
        apply_options.set_enum(PARAMETER_DATA_TYPES,
                                ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY)
        apply_options.set_enum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE)
        apply_options.set_enum(PARAMETER_COMMENTS, CommentChoices.EXCLUDE)

    @staticmethod
    def test_apply_markup_replace_signature_only_2_to_3_this_to_this():
        use_match("0x00411570", "0x00411560")

        check_signatures("void use(Gadget * this, Person * person)",
                         "void FUN_00411da0(void * this, undefined4 param_1)")

        set_return_type(source_function=FloatDataType(), source_type=SourceType.IMPORTED)

        parameter_comment = "Source Parameter 2 comment."
        set_parameter_comment(1, parameter_comment)
        set_parameter_comment(destination_function=1, parameter_comment="Destination Parameter 2 comment.")

        check_signatures("float use(Gadget * this, Person * person)",
                         "void FUN_00411da0(void * this, undefined4 param_1)")

    @staticmethod
    def test_apply_markup_replace_signature_only_3_to_2_this_to_this():
        use_match("0x00411570", "0x0041160")

        check_signatures("float use(Gadget * this, Person * person)",
                         "void FUN_00411da0(void * this, undefined4 param_1)")

    @staticmethod
    def test_apply_markup_replace_signature_only_2_to_3_this_to_this():
        use_match("0x00411570", "0x0041160")

        check_signatures("float use(Gadget * this, Person * person)",
                         "void FUN_00411da0(void * this, undefined4 param_1)")

    @staticmethod
    def test_apply_markup_replace_signature_only_2_to_3_this_to_this():
        use_match("0x00411570", "0x0041160")

        check_signatures("float use(Gadget * this, Person * person)",
                         "void FUN_00411da0(void * this, undefined4 param_1)")

    @staticmethod
    def test_apply_markup_replace_signature_only_2_to_3_this_to_this():
        use_match("0x00411570", "0x0041160")

        check_signatures("float use(Gadget * this, Person * person)",
                         "void FUN_00411da0(void * this, undefined4 param_1)")

    @staticmethod
    def testApplyMarkupReplaceSignatureOnly2To3This():
        use_match("0x00411570", "0x0041160")

        check_signatures("float use(Gadget * this, Person * person)",
                         "void FUN_00411da0(void * this, undefined4 param_1)")
``