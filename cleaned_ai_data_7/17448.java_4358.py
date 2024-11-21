class ResultColumn:
    def __init__(self, expression: 'Expression', alias=None):
        self.expression = expression
        self.alias = alias

    @property
    def data_type(self) -> TSDataType:
        return self._data_type

    @data_type.setter
    def data_type(self, value: TSDataType):
        self._data_type = value


class Expression:
    pass  # This class is not implemented in the given Java code. It's assumed to be a custom class.


def concat(prefix_paths: list[PartialPath], result_columns: list['ResultColumn']) -> None:
    if len(result_columns) > 1 and alias := result_column.alias:
        raise LogicalOptimizeException(f"Alias '{alias}' can only be matched with one time series")


for expression in expressions:
    result_columns.append(ResultColumn(expression, alias))


def remove_wildcards(wildcards_remover: WildcardsRemover, result_columns: list['ResultColumn']) -> None:
    if len(result_columns) > 1 and alias := result_column.alias:
        raise LogicalOptimizeException(f"Alias '{alias}' can only be matched with one time series")

    for expression in expressions:
        result_columns.append(ResultColumn(expression, alias))


def collect_paths(self: 'ResultColumn') -> set[PartialPath]:
    path_set = set()
    self.expression.collect_paths(path_set)
    return path_set


class LogicalOptimizeException(Exception):
    pass
