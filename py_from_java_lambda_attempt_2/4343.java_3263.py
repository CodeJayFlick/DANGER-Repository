Here is the translation of the Java code to Python:
```
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
```
Note that I did not implement the `IsAsciiColumnConstraint`, etc. classes as they were not provided in the original Java code. You would need to add your own implementations for these classes depending on what you want them to do.

Also, Python does not have a direct equivalent of Java's `Collection` interface or `ArrayList`. Instead, I used a list comprehension to create a list of constraints.