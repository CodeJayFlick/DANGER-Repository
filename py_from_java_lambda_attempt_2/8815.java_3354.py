Here is the translation of the Java code into Python:

```Python
class VTAssociationMarkupStatus:
    INITIALIZED = 0x1
    HAS_UNEXAMINED = 0x2
    HAS_APPLIED = 0x4
    HAS_REJECTED = 0x8
    HAS_DONT_CARE = 0x10
    HAS_DONT_KNOW = 0x20
    HAS_ERRORS = 0x40

    def __init__(self, status=0):
        self.status = status

    @property
    def is_initialized(self):
        return bool(self.status & VTAssociationMarkupStatus.INITIALIZED)

    @property
    def has_unexamined_markup(self):
        return bool(self.status & VTAssociationMarkupStatus.HAS_UNEXAMINED)

    @property
    def has_applied_markup(self):
        return bool(self.status & VTAssociationMarkupStatus.HAS_APPLIED)

    @property
    def has_rejected_markup(self):
        return bool(self.status & VTAssociationMarkupStatus.HAS_REJECTED)

    @property
    def has_dont_care_markup(self):
        return bool(self.status & VTAssociationMarkupStatus.HAS_DONT_CARE)

    @property
    def has_dont_know_markup(self):
        return bool(self.status & VTAssociationMarkupStatus.HAS_DONT_KNOW)

    @property
    def has_errors(self):
        return bool(self.status & VTAssociationMarkupStatus.HAS_ERRORS)

    @property
    def status_value(self):
        return self.status

    def __eq__(self, other):
        if not isinstance(other, VTAssociationMarkupStatus):
            return False
        return self.status == other.status

    def __hash__(self):
        return hash(self.status)

    @property
    def is_fully_applied(self):
        return self.status in [VTAssociationMarkupStatus.INITIALIZED,
                               VTAssociationMarkupStatus.INITIALIZED |
                               VTAssociationMarkupStatus.HAS_APPLIED]

    def get_description(self):
        description = []
        if self.has_unexamined_markup:
            description.append("Has one or more unexamined markup items.")
        if self.has_applied_markup:
            description.append("Has one or more applied markup items.")
        if self.has_errors:
            description.append("Has one or more markup items that failed to apply.")
        if self.has_dont_care_markup:
            description.append("Has one or more \"Don't Care\" markup items.")
        if self.has_dont_know_markup:
            description.append("Has one or more \"Don't Know\" markup items.")
        return "\n".join(description)

    def __str__(self):
        return f"Markup Status: {self.get_description()}"

    def __repr__(self):
        return str(self)
```

Note that Python does not have an exact equivalent to Java's `Comparable` interface, so I did not include it in the translation. Also, Python has a different way of handling bit manipulation and bitwise operations compared to Java, which is why you won't see any direct equivalents to Java code like `status & HAS_UNEXAMINED`.