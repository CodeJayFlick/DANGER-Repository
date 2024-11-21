class AbstractWrapperTypeColumnRenderer:
    def __init__(self):
        pass

    # Overridden to only allow the constraint filtering mechanism.
    def get_column_constraint_filter_mode(self) -> str:
        return "ALLOW_CONSTRAINTS_FILTER_ONLY"

    def get_filter_string(self, t: object, settings: dict) -> str:
        raise Exception("We don't use String values for filtering wrapper types")
