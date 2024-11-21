class VTMatchApplyChoices:
    class ReplaceChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        REPLACE = "Replace"

    class ReplaceDefaultChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        REPLACE_ALWAYS = "Replace Always"
        REPLACE_DEFAULT_ONLY = "Replace Default Only"

    class ReplaceDataChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        REPLACE_FIRST_DATA_ONLY = "Replace First Data Only"
        REPLACE_ALL_DATA = "Replace All Data"
        REPLACE_UNDEFINED_DATA_ONLY = "Replace Undefined Data Only"

    class CommentChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        APPEND_TO_EXISTING = "Add To Existing"
        OVERWRITE_EXISTING = "Replace Existing"

    class FunctionNameChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        ADD = "Add"
        ADD_AS_PRIMARY = "Add As Primary"
        REPLACE_ALWAYS = "Replace Always"
        REPLACE_DEFAULT_ONLY = "Replace Default Only"

    class LabelChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        ADD = "Add"
        ADD_AS_PRIMARY = "Add As Primary"
        REPLACE_ALL = "Replace All"
        REPLACE_DEFAULT_ONLY = "Replace Default Only"

    class ParameterSourceChoices(enum.Enum):
        ENTIRE_PARAMETER_SIGNATURE_MARKUP = "Use Entire Parameters Signature"
        INDIVIDUAL_PARAMETER_MARKUP = "Use Individual Parameter Items"

    class CallingConventionChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        SAME_LANGUAGE = "Replace If Same Language"
        NAME_MATCH = "Replace If Has Named Convention"

    class FunctionSignatureChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        REPLACE = "Replace"
        WHEN_SAME_PARAMETER_COUNT = "Replace When Same Parameter Count"

    class ParameterDataTypeChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        REPLACE_UNDEFINED_DATA_TYPES_ONLY = "Replace Undefined Data Types Only"
        REPLACE = "Replace"

    class FunctionAttributeChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        REPLACE = "Replace"
        WHEN_TAKING_SIGNATURE = "Replace When Replacing Signature"

    class SourcePriorityChoices(enum.Enum):
        EXCLUDE = "Do Not Apply"
        REPLACE_DEFAULTS_ONLY = "Replace Default Only"
        REPLACE = "Replace"
        PRIORITY_REPLACE = "Priority Replace"

    class HighestSourcePriorityChoices(enum.Enum):
        USER_PRIORITY_HIGHEST = "User"
        IMPORT_PRIORITY_HIGHEST = "Import"


# Example usage:
print(VTMatchApplyChoices.ReplaceChoices.REPLACE)
