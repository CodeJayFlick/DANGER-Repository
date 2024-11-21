Here is the translation of the Java code into equivalent Python:

```Python
class VTOptionDefines:
    # Accept Options
    ACCEPT_MATCH_OPTIONS_NAME = "Accept Match Options"
    AUTO_CREATE IMPLIED_MATCH = f"{ACCEPT_MATCH_OPTIONS_NAME}.Auto Create Implied Matches"
    APPLY_FUNCTION_NAME_ON_ACCEPT = f"{ACCEPT_MATCH_OPTIONS_NAME}.Automatically Apply Function Name on Accept"
    APPLY_DATA_NAME_ON_ACCEPT = f"{ACCEPT_MATCH_OPTIONS_NAME}.Automatically Apply Data Label on Accept"

    # Apply Options

    APPLY_MARKUP_OPTIONS_NAME = "Apply Markup Options"
    DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS = False
    DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS = False
    DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY = False
    DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE = ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY

    class ReplaceDataChoices:
        REPLACE_UNDEFINED_DATA_ONLY = "Replace Undefined Data Only"

    DEFAULT_OPTION_FOR_FUNCTION_NAME = FunctionNameChoices.ADD_AS_PRIMARY
    DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE = FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT
    DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE = ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY

    class FunctionNameChoices:
        ADD_AS_PRIMARY = "Add As Primary"

    class FunctionSignatureChoices:
        WHEN_SAME_PARAMETER_COUNT = "When Same Parameter Count"

    class ParameterDataTypeChoices:
        REPLACE_UNDEFINED_DATA_TYPES_ONLY = "Replace Undefined Data Types Only"

    DEFAULT_OPTION_FOR_INLINE = ReplaceChoices.REPLACE
    DEFAULT_OPTION_FOR_NO_RETURN = ReplaceChoices.REPLACE

    class CallingConventionChoices:
        SAME_LANGUAGE = "Same Language"

    DEFAULT_OPTION_FOR_CALL_FIXUP = ReplaceChoices.REPLACE
    DEFAULT_OPTION_FOR_VAR_ARGS = ReplaceChoices.REPLACE

    DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES = ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY
    DEFAULT_OPTION_FOR_PARAMETER_NAMES = SourcePriorityChoices.PRIORITY_REPLACE
    DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY = HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST

    class CommentChoices:
        APPEND_TO_EXISTING = "Append To Existing"

    DEFAULT_OPTION_FOR_COMMENT = CommentChoices.APPEND_TO_EXISTING

    FUNCTION_NAME = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Name"
    FUNCTION_RETURN_TYPE = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Return Type"
    LABELS = f"{APPLY_MARKUP_OPTIONS_NAME}.Labels"
    PLATE_COMMENT = f"{APPLY_MARKUP_OPTIONS_NAME}.Plate Comment"
    PRE_COMMENT = f"{APPLY_MARKUP_OPTIONS_NAME}.Pre Comment"
    END_OF_LINE_COMMENT = f"{APPLY_MARKUP_OPTIONS_NAME}.End of Line Comment"
    REPEATABLE_COMMENT = f"{APPLY_MARKUP_OPTIONS_NAME}.Repeatable Comment"
    POST_COMMENT = f"{APPLY_MARKUP_OPTIONS_NAME}.Post Comment"

    DATA_MATCH_DATA_TYPE = f"{APPLY_MARKUP_OPTIONS_NAME}.Data Match Data Type"
    FUNCTION_SIGNATURE = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Signature"
    CALLING_CONVENTION = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Calling Convention"
    INLINE = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Inline"
    NO_RETURN = f"{APPLY_MARKUP_OPTIONS_NAME}.Function No Return"

    PARAMETER_DATA_TYPES = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Parameter Data Types"
    PARAMETER_NAMES = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Parameter Names"
    HIGHEST_NAME_PRIORITY = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Parameter Names Highest Name Priority"
    PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Parameter Names Replace If Same Priority"

    PARAMETER_COMMENTS = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Parameter Comments"
    VAR_ARGS = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Var Args"
    CALL_FIXUP = f"{APPLY_MARKUP_OPTIONS_NAME}.Function Call Fixup"

    IGNORE_INCOMPLETE_MARKUP_ITEMS = f"{APPLY_MARKUP_OPTIONS_NAME}.Set Incomplete Markup Items To Ignored"
    IGNORE_EXCLUDED_MARKUP_ITEMS = f"{APPLY_MARKUP_OPTIONS_NAME}.Set Excluded Markup Items To Ignored"

    DISPLAY_APPLY_MARKUP_OPTIONS = f"{APPLY_MARKUP_OPTIONS_NAME}{Options.DELIMITER}Display Apply Markup Options"


class HighestSourcePriorityChoices:
    USER_PRIORITY_HIGHEST = "User Priority Highest"
```

Note that I've used Python's `f` string notation to create the strings, and created separate classes for some of the enums.