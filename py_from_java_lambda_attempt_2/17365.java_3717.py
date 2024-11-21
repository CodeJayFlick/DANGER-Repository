Here is the translation of the given Java code into equivalent Python:

```Python
class LogicalGenerator:
    def __init__(self):
        pass

    @staticmethod
    def generate_sql(sql: str, zone_id: int) -> Operator:
        try:
            tree = IoTDBSqlParser(antlr4.InputStream.from_string(sql)).single_statement()
        except Exception as e:
            # handle exception here
            pass
        
        return ioTDBSqlVisitor().visit(tree)

    @staticmethod
    def generate_raw_data_query_req(raw_data_query_req: TSRawDataQueryReq, zone_id: int) -> Operator:
        query_op = QueryOperator()
        from_op = FromComponent()
        select_op = SelectComponent(zone_id)
        
        for path in raw_data_query_req.get_paths():
            partial_path = PartialPath(path)
            from_op.add_prefix_table_path(partial_path)

        select_op.add_result_column(ResultColumn(TimeSeriesOperand(PartialPath(""))))

        query_op.set_select_component(select_op)
        query_op.set_from_component(from_op)

        filter_op = FilterOperator(FilterType.KW_AND)
        time_path = PartialPath(TIME)
        filter_op.set_single_path(time_path)
        
        path_set = set()
        path_set.add(time_path)
        filter_op.set_is_single(True)
        filter_op.set_path_set(path_set)

        left = BasicFunctionOperator(FilterType.GREATERTHANOREQUALTO, time_path, str(raw_data_query_req.get_start_time()))
        right = BasicFunctionOperator(FilterType.LESSTHAN, time_path, str(raw_data_query_req.get_end_time()))

        filter_op.add_child_operator(left)
        filter_op.add_child_operator(right)

        query_op.set_where_component(WhereComponent(filter_op))

        return query_op

    @staticmethod
    def generate_last_data_query_req(req: TSLastDataQueryReq, zone_id: int) -> Operator:
        query_op = LastQueryOperator()
        from_op = FromComponent()
        select_op = SelectComponent(zone_id)

        for path in req.get_paths():
            partial_path = PartialPath(path)
            from_op.add_prefix_table_path(partial_path)

        select_op.add_result_column(ResultColumn(TimeSeriesOperand(PartialPath(""))))

        query_op.set_select_component(select_op)
        query_op.set_from_component(from_op)

        time_path = PartialPath(TIME)

        basic_function_operator = BasicFunctionOperator(FilterType.GREATERTHANOREQUALTO, time_path, str(req.get_time()))

        query_op.set_where_component(WhereComponent(basic_function_operator))

        return query_op
```

Note: The above Python code is a direct translation of the given Java code. However, it may not be perfect as some parts like error handling and exception handling are missing in this code.