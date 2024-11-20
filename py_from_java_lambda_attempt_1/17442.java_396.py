Here is the translation of the given Java code into Python:

```Python
class BinaryExpression:
    def __init__(self, left_expression: 'BinaryExpression', right_expression: 'BinaryExpression'):
        self.left_expression = left_expression
        self.right_expression = right_expression

    @property
    def is_time_series_generating_function_expression(self):
        return True

    def concat(self, prefix_paths: list, result_expressions: list) -> None:
        left_expressions = []
        self.left_expression.concat(prefix_paths, left_expressions)
        
        right_expressions = []
        self.right_expression.concat(prefix_paths, right_expressions)

        self.reconstruct(left_expressions, right_expressions, result_expressions)

    def remove_wildcards(self, wildcards_remover: object, result_expressions: list) -> None:
        left_expressions = []
        self.left_expression.remove_wildcards(wildcards_remover, left_expressions)
        
        right_expressions = []
        self.right_expression.remove_wildcards(wildcards_remover, right_expressions)

        self.reconstruct(left_expressions, right_expressions, result_expressions)

    def reconstruct(self, left_expressions: list, right_expressions: list, result_expressions: list) -> None:
        for le in left_expressions:
            for re in right_expressions:
                operator = self.operator()
                if operator == "+":
                    result_expressions.append(AdditionExpression(le, re))
                elif operator == "-":
                    result_expressions.append(SubtractionExpression(le, re))
                elif operator == "*":
                    result_expressions.append(MultiplicationExpression(le, re))
                elif operator == "/":
                    result_expressions.append(DivisionExpression(le, re))
                elif operator == "%":
                    result_expressions.append(ModuloExpression(le, re))

    def collect_paths(self, path_set: set) -> None:
        self.left_expression.collect_paths(path_set)
        self.right_expression.collect_paths(path_set)

    def construct_udf_executors(self, expression_name2_executor: dict, zone_id: object) -> None:
        self.left_expression.construct_udf_executors(expression_name2_executor, zone_id)
        self.right_expression.construct_udf_executors(expression_name2_executor, zone_id)

    def update_statistics_for_memory_assigner(self, memory_assigner: object) -> None:
        self.left_expression.update_statistics_for_memory_assigner(memory_assigner)
        self.right_expression.update_statistics_for_memory_assigner(memory_assigner)
        memory_assigner.increase_expression_reference(self)

    def construct_intermediate_layer(self,
                                       query_id: int,
                                       udtf_plan: object,
                                       raw_time_series_input_layer: object,
                                       expression_intermediate_layer_map: dict,
                                       expression_data_type_map: dict,
                                       memory_assigner: object) -> 'IntermediateLayer':
        if not expression_intermediate_layer_map.get(self):
            memory_budget_in_mb = memory_assigner.assign()
            
            left_parent_intermediate_layer = self.left_expression.construct_intermediate_layer(
                query_id, udtf_plan, raw_time_series_input_layer,
                expression_intermediate_layer_map, expression_data_type_map, memory_assigner
            )
            right_parent_intermediate_layer = self.right_expression.construct_intermediate_layer(
                query_id, udtf_plan, raw_time_series_input_layer,
                expression_intermediate_layer_map, expression_data_type_map, memory_assigner
            )

            transformer = self.construct_transformer(left_parent_intermediate_layer.point_reader(), 
                                                      right_parent_intermediate_layer.point_reader())
            
            expression_data_type_map[self] = transformer.data_type
            
            if memory_assigner.get_reference(self) == 1:
                intermediate_layer = SingleInputColumnSingleReferenceIntermediateLayer(
                    self, query_id, memory_budget_in_mb, transformer
                )
            else:
                intermediate_layer = SingleInputColumnMultiReferenceIntermediateLayer(
                    self, query_id, memory_budget_in_mb, transformer
                )

            expression_intermediate_layer_map[self] = intermediate_layer

        return expression_intermediate_layer_map.get(self)

    def construct_transformer(self, left_parent_point_reader: object, right_parent_point_reader: object) -> 'ArithmeticBinaryTransformer':
        raise NotImplementedError("construct_transformer")

    @property
    def operator(self):
        raise NotImplementedError("operator")

    def __str__(self) -> str:
        return f"{self.left_expression} {self.operator()} {self.right_expression}"
```

Note that I've used Python's type hinting feature to specify the types of variables and function parameters. This is not strictly necessary, but it can help with code readability and catch potential errors at runtime.

Also note that some methods in this class are abstract (i.e., they raise a `NotImplementedError` when called), which means you'll need to provide implementations for these methods if you want to use instances of this class.