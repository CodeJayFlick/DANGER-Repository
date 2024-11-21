class InOperator:
    def __init__(self, filter_type: str, path: str, not_: bool, values: set):
        self.filter_type = filter_type
        self.path = path
        self.not_ = not_
        self.values = values

    @property
    def get_values(self) -> set:
        return self.values

    @property
    def get_not(self) -> bool:
        return self.not_

    def reverse_func(self):
        self.not_ = not self.not_

    def transform_to_single_query_filter(
            self, path_ts_data_type: dict
    ) -> tuple[Callable[[set], IUnaryExpression], str]:
        if self.path not in path_ts_data_type:
            raise MetadataException(f"given seriesPath {self.path} don't exist in metadata")

        type_ = path_ts_data_type[self.path]
        ret

        match type_:
            case "INT32":
                integer_values = set(int(val) for val in self.values)
                return In.get_unary_expression(self.path, integer_values, self.not_), self.path
            case "INT64":
                long_values = set(long(val) for val in self.values)
                return In.get_unary_expression(self.path, long_values, self.not_), self.path
            case "BOOLEAN":
                boolean_values = set(bool(val) for val in self.values)
                return In.get_unary_expression(self.path, boolean_values, self.not_), self.path
            case "FLOAT":
                float_values = set(float(val) for val in self.values)
                return In.get_unary_expression(self.path, float_values, self.not_), self.path
            case "DOUBLE":
                double_values = set(double(val) for val in self.values)
                return In.get_unary_expression(self.path, double_values, self.not_), self.path
            case "TEXT":
                binary_values = {Binary(val.encode()) if (val.startswith("'") and val.endswith("'")) or (
                        val.startswith('"') and val.endswith('"')) else Binary(val) for val in self.values}
                return In.get_unary_expression(self.path, binary_values, self.not_), self.path
            case _:
                raise LogicalOperatorException(f"Unsupported type {type_}")

    def show_tree(self, space_num: int):
        sc = StringContainer()
        for i in range(space_num):
            sc.add_tail("   ")
        sc.add_tail(self.path, get_filter_symbol(), not_, self.values)
        return str(sc)

    def copy(self) -> "InOperator":
        ret = InOperator(
            filter_type=self.filter_type,
            path=PartialPath(self.path),
            not_=self.not_,
            values=set(self.values)
        )
        ret.is_leaf = is_leaf
        ret.is_single = is_single
        return ret

    def __str__(self):
        values_list = list(self.values)
        values_list.sort()
        return f"[{self.path}{get_filter_symbol()}{not_} {values_list}]"

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if not isinstance(other, InOperator):
            return False

        that = other
        return (
                Objects.equals(self.path, that.path)
                and set(self.values).issuperset(set(that.values))
                and len(self.values) == len(that.values)
                and self.not_ == that.not_
        )

    def __hash__(self) -> int:
        return hash((super().__hash__(), self.path, not_, frozenset(self.values)))

class In:
    @staticmethod
    def get_unary_expression(path: str, values: set[Comparable], not_: bool):
        if path == "time":
            return GlobalTimeExpression(TimeFilter.in(set(long(val) for val in values), not_))
        else:
            return SingleSeriesExpression(path, ValueFilter.in(values, not_))

    @staticmethod
    def get_value_filter(value: Comparable) -> Filter:
        return ValueFilter.not_eq(value)
