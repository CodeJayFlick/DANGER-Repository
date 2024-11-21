class WildcardsRemover:
    def __init__(self):
        self.soffset = 0
        self.current_offset = 0
        self.current_limit = float('inf')

    def remove_wildcard_from(self, path: list) -> list:
        try:
            pair = IoTDB.meta_manager.get_flat_measurement_paths_with_alias(path, self.current_limit, self.current_offset)
            consumed += pair.right
            if self.current_offset != 0:
                delta = self.current_offset - pair.right
                self.current_offset = max(delta, 0)
                if delta < 0:
                    self.current_limit += delta
                else:
                    self.current_limit -= pair.right
            return pair.left

        except MetadataException as e:
            raise LogicalOptimizeException(f"Error occurred when removing star: {e.message}")

    def remove_wildcards_from(self, expressions: list) -> list:
        extended_expressions = []
        for origin_expression in expressions:
            actual_expressions = []
            origin_expression.remove_wildcards(self, actual_expressions)
            if not actual_expressions:
                return []

            extended_expressions.append(actual_expressions)

        actual_expressions = ConcatPathOptimizer.cartesian_product(extended_expressions, [], 0, [])

        remaining_expressions = []
        for actual_expression in actualExpressions:
            if self.current_offset != 0:
                self.current_offset -= 1
                continue

            elif self.current_limit != 0:
                self.current_limit -= 1
            else:
                break

            remaining_expressions.append(actual_expression)

        consumed += len(actual_expressions)
        return remaining_expressions

    def check_if_path_number_is_over_limit(self, result_columns: list) -> bool:
        max_query_deduplicated_path_num = IoTDBDescriptor.getInstance().getConfig().getMaxQueryDeduplicatedPathNum()
        if self.current_limit == 0:
            if max_query_deduplicated_path_num < len(result_columns):
                raise PathNumOverLimitException(max_query_deduplicated_path_num)
            return True
        return False

    def check_if_soffset_is_exceeded(self, result_columns: list) -> None:
        if consumed == 0 and self.soffset != 0 or not result_columns:
            raise LogicalOptimizeException(f"The value of SOFFSET ({self.soffset}) is equal to or exceeds the number of sequences ({consumed}) that can actually be returned.")
