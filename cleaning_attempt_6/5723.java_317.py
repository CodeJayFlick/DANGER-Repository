class GhidraOptions:
    DELIMITER = Options.DELIMITER  # Assuming Options class exists in your scope
    
    CATEGORY_BROWSER_DISPLAY = "Listing Display"
    CATEGORY_ANNOTATION_NAVIGATION_MARKERS = "Navigation Markers"

    OPTION_BASE_FONT = "BASE FONT"
    
    CATEGORY_FLOW_OPTIONS = "Selection by Flow"
    OPTION_FOLLOW_COMPUTED_CALL = "Follow computed call"
    OPTION_FOLLOW_CONDITIONAL_CALL = "Follow conditional call"
    OPTION_FOLLOW_UNCONDITIONAL_CALL = "Follow unconditional call"
    OPTION_FOLLOW_COMPUTED_JUMP = "Follow computed jump"
    OPTION_FOLLOW_CONDITIONAL_JUMP = "Follow conditional jump"
    OPTION_FOLLOW_UNCONDITIONal_JUMP = "Follow unconditional jump"
    OPTION_FOLLOW_POINTERS = "Follow pointers"

    OPTION_SEARCH_LIMIT = "Search Limit"
    
    CATEGORY_AUTO_ANALYSIS = "Auto Analysis"
    CATEGORY_BROWSER_FIELDS = "Listing Fields"
    MNEMONIC_GROUP_TITLE = "Mnemonic Field"
    OPERAND_GROUP_TITLE = "Operands Field"
    LABEL_GROUP_TITLE = "Label Field"
    OPTION_SHOW_BLOCK_NAME = "Show Block Names"

    CATEGORY_BROWSER_POPUPS = "Listing Popups"
    CATEGORY_DECOMPILER_POPUPS = "Decompiler Popups"

    OPTION_NUMERIC_FORMATTING = "Use C-liked Numeric Formatting for Addresses"
    
    MAX_GO_TO_ENTRIES_OPTION = "Max Goto Entries"

    SHOW_BLOCK_NAME_OPTION = OPERAND_GROUP_TITLE + DELIMITER + OPTION_SHOW_BLOCK_NAME
    DISPLAY_NAMESPACE = "Display Namespace"
    NAVIGATION_OPTIONS = "Navigation"
    NAVIGATION_RANGE_OPTION = "Range Navigation"
    EXTERNAL_NAVIGATION_OPTION = "External Navigation"
    FOLLOW_INDIRECTION_NAVIGATION_OPTION = "Follow Indirection"

    HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME = "Highlight Cursor Line Color"
    DEFAULT_CURSOR_LINE_COLOR = (232, 242, 254)
    
    HIGHLIGHT_CURSOR_LINE_OPTION_NAME = "Highlight Cursor Line"
    CURSOR_HIGHLIGHT_GROUP = "Cursor Text Highlight"
    CURSOR_HIGHLIGHT_BUTTON_NAME = CURSOR_HIGHLIGHT_GROUP + DELIMITER + "Mouse Button To Activate"
    HIGHLIGHT_COLOR_NAME = CURSOR_HIGHLIGHT_GROUP + DELIMITER + "Highlight Color"

    class CursorMouseButtonNames:
        LEFT = 1
        MIDDLE = 2
        RIGHT = 3

    OPTION_SELECTION_COLOR = "Selection Colors. Selection Color"
    DEFAULT_SELECTION_COLOR = (180, 255, 180)
    
    OPTION_HIGHLIGHT_COLOR = "Selection Colors.Highlight Color"
    DEFAULT_HIGHLIGHT_COLOR = (255, 255, 180)

    APPLY_ENABLED_OPTION_NAME = "apply.enabled"

