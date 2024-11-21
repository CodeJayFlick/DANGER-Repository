Here is the translation of the Java interface `ListingMergeConstants` into a Python class:

```Python
class ListingMergeConstants:
    CANCELED = -1
    ASK_USER = 0
    INFO_ROW = 0
    KEEP_ORIGINAL = 1
    KEEP_LATEST = 2
    KEEP_MY = 4
    KEEP_RESULT = 8
    KEEP_BOTH = KEEP_LATEST | KEEP_MY
    KEEP_ALL = KEEP_LATEST | KEEP_MY | KEEP_ORIGINAL
    REMOVE_LATEST = 8
    RENAME_LATEST = 16
    REMOVE_MY = 32
    RENAME_MY = 64

    TRUNCATE_LENGTH = 160

    RESULT_TITLE = "Result"
    ORIGINAL_TITLE = "Original"
    LATEST_TITLE = "Latest"
    MY_TITLE = "My"

    LATEST_LIST_BUTTON_NAME = "LatestListRB"
    CHECKED_OUT_LIST_BUTTON_NAME = "CheckedOutListRB"
    LATEST_BUTTON_NAME = "LatestVersionRB"
    CHECKED_OUT_BUTTON_NAME = "CheckedOutVersionRB"
    ORIGINAL_BUTTON_NAME = "OriginalVersionRB"
    RESULT_BUTTON_NAME = "ResultVersionRB"
    LATEST_CHECK_BOX_NAME = "LatestVersionCheckBox"
    CHECKED_OUT_CHECK_BOX_NAME = "CheckedOutVersionCheckBox"
    ORIGINAL_CHECK_BOX_NAME = "OriginalVersionCheckBox"
    LATEST_LABEL_NAME = "LatestVersionLabel"
    CHECKED_OUT_LABEL_NAME = "CheckedOutVersionLabel"
    ORIGINAL_LABEL_NAME = "OriginalVersionLabel"

    REMOVE_LATEST_BUTTON_NAME = "RemoveLatestRB"
    RENAME_LATEST_BUTTON_NAME = "RenameLatestRB"
    REMOVE_CHECKED_OUT_BUTTON_NAME = "RemoveCheckedOutRB"
    RENAME_CHECKED_OUT_BUTTON_NAME = "RenameCheckedOutRB"
```

Note that Python does not have an exact equivalent to Java's `interface` keyword. Instead, we use a class with no methods and only constants defined as attributes of the class.