import collections

class ViewStringsColumnConstraintProvider:
    def get_column_constraints(self):
        return [
            IsAsciiColumnConstraint(),
            IsNotAsciiColumnConstraint(),
            HasEncodingErrorColumnConstraint(),
            HasTranslationValueColumnConstraint(),
            DoesNotHaveTranslationValueColumnConstraint()
        ]

class IsAsciiColumnConstraint:
    pass  # implementation not provided

class IsNotAsciiColumnConstraint:
    pass  # implementation not provided

class HasEncodingErrorColumnConstraint:
    pass  # implementation not provided

class HasTranslationValueColumnConstraint:
    pass  # implementation not provided

class DoesNotHaveTranslationValueColumnConstraint:
    pass  # implementation not provided
