class VTMarkupItemStatus:
    UNAPPLIED = ("Unapplied", True, False)
    ADDED = ("Applied (Added)", False, True)
    REPLACED = ("Applied (Replaced)", False, True)
    FAILED_APPLY = ("Apply Failed", False, False)
    DONT_CARE = ("Don't Care", True, False)
    DONT_KNOW = ("Don't Know", True, False)
    REJECTED = ("Rejected", False, False)
    SAME = ("Destination has same value", False, False)
    CONFLICT = ("Conflicting item is applied", False, False)

    def __init__(self, description, appliable, unappliable):
        self.description = description
        self.appliable = appliable
        self.unappliable = unappliable

    @property
    def appliable(self):
        return self.appliable

    @property
    def unappliable(self):
        return self.unappliable

    @property
    def is_default(self):
        return self in [VTMarkupItemStatus.SAME, VTMarkupItemStatus.CONFLICT, VTMarkupItemStatus.UNAPPLIED]

    def __str__(self):
        return self.description
