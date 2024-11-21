class RowByRowAccessStrategy:
    def check(self):
        # nothing needs to be checked
        pass

    def get_access_strategy_type(self) -> str:
        return "ROW_BY_ROW"
