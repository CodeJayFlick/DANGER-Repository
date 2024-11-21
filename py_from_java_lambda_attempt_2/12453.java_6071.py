Here is the translation of the given Java code into equivalent Python:

```Python
class GhidraLanguagePropertyKeys:
    def __init__(self):
        pass

    CUSTOM_DISASSEMBLER_CLASS = "customDisassemblerClass"
    ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS = "allowOffcutReferencesToFunctionStarts"
    USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES = "useOperandReferenceAnalyzerSwitchTables"
    IS_TMS320_FAMILY = "isTMS320Family"

    PARALLEL_INSTRUCTION_HELPER_CLASS = "parallelInstructionHelperClass"
    ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE = "addressesDoNotAppearDirectlyInCode"
    USE_NEW_FUNCTION_STACK_ANALYSIS = "useNewFunctionStackAnalysis"
    EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS = "emulateInstructionStateModifierClass"

    PCODE_INJECT_LIBRARY_CLASS = "pcodeInjectLibraryClass"
    ENABLE_SHARED_RETURN_ANALYSIS = "enableSharedReturnAnalysis"
    ENABLE_NO_RETURN_ANALYSIS = "enableNoReturnAnalysis"
    RESET_CONTEXT_ON_UPGRADE = "resetContextOnUpgrade"
    MINIMUM_DATA_IMAGE_BASE = "minimumDataImageBase"

# Example usage:
ghidra_language_property_keys = GhidraLanguagePropertyKeys()
print(ghidra_language_property_keys.CUSTOM_DISASSEMBLER_CLASS)
```

Note that Python does not have an exact equivalent to Java's `public final class` declaration. The above code defines a simple Python class with the same property names as in the original Java code, but without any access modifiers or final keyword.