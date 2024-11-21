Here is the translation of the given Java code into equivalent Python:

```Python
class Expression:
    def __init__(self):
        self.expression_string = None

    def is_aggregation_function_expression(self) -> bool:
        return False

    def is_time_series_generating_function_expression(self) -> bool:
        return False

    def concat(self, prefix_paths: list, result_expressions: list):
        pass  # abstract method implementation left out for brevity

    def remove_wildcards(self, wildcards_remover: object, result_expressions: list) -> None:
        raise LogicalOptimizeException()  # Python equivalent of Java's throws clause

    def collect_paths(self, path_set: set):
        pass  # abstract method implementation left out for brevity

    def construct_udf_executors(self, expression_name2_executor: dict, zone_id: object) -> None:
        pass  # abstract method implementation left out for brevity

    def update_statistics_for_memory_assigner(self, memory_assigner: object):
        pass  # abstract method implementation left out for brevity

    def construct_intermediate_layer(self,
                                       query_id: int,
                                       udtf_plan: object,
                                       raw_time_series_input_layer: object,
                                       expression_intermediate_layer_map: dict,
                                       expression_data_type_map: dict,
                                       memory_assigner: object) -> IntermediateLayer:
        raise QueryProcessException()  # Python equivalent of Java's throws clause
        return None

    def get_expression_string(self):
        if self.expression_string is None:
            self.expression_string = str(self)
        return self.expression_string

    def __hash__(self):
        return hash(self.get_expression_string())

    def __eq__(self, other: object) -> bool:
        if self == other:
            return True
        if not isinstance(other, Expression):
            return False
        return self.get_expression_string() == (other).get_expression_string()
```

Note that Python does not have direct equivalents of Java's `abstract` keyword or its `throws` clause. The abstract methods in the given code are left out for brevity and would need to be implemented according to their specific requirements.