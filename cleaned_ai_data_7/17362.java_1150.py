class Planner:
    def __init__(self):
        pass  # do nothing

    @staticmethod
    def parse_sql_to_physical_plan(sql_str: str, zone_id) -> PhysicalPlan:
        operator = LogicalGenerator.generate(sql_str, zone_id)
        LogicalChecker.check(operator)
        optimized_operator = Planner.logical_optimize(operator)
        return PhysicalGenerator().transform_to_physical_plan(optimized_operator)

    @staticmethod
    def cq_query_operator_to_group_by_time_plan(query_operator: QueryOperator) -> GroupByTimePlan:
        query_operator = Planner.logical_optimize(query_operator)
        return PhysicalGenerator().transform_to_physical_plan(query_operator)

    @staticmethod
    def raw_data_query_req_to_physical_plan(raw_data_query_req, zone_id):
        operator = LogicalGenerator.generate(raw_data_query_req, zone_id)
        LogicalChecker.check(operator)
        optimized_operator = Planner.logical_optimize(operator)
        return PhysicalGenerator().transform_to_physical_plan(optimized_operator)

    @staticmethod
    def last_data_query_req_to_physical_plan(last_data_query_req, zone_id) -> PhysicalPlan:
        operator = LogicalGenerator.generate(last_data_query_req, zone_id)
        LogicalChecker.check(operator)
        optimized_operator = Planner.logical_optimize(operator)
        return PhysicalGenerator().transform_to_physical_plan(optimized_operator)

    @staticmethod
    def logical_optimize(operator: Operator):
        if isinstance(operator, QueryOperator) or isinstance(operator, SelectIntoOperator):
            try:
                operator = optimize_query_operator(operator)
            except (LogicalOperatorException, PathNumOverLimitException):
                pass  # handle exceptions as needed

        return operator


def optimize_query_operator(root: QueryOperator) -> QueryOperator:
    root = concat_path_optimizer.transform(root)

    where_component = root.get_where_component()
    if where_component is None:
        return root

    filter = where_component.get_filter_operator()
    filter = remove_not_optimizer.optimize(filter)
    filter = dnf_filter_optimizer.optimize(filter)
    filter = merge_single_filter_optimizer.optimize(filter)
    where_component.set_filter_operator(filter)

    return root


def optimize_select_into_operator(operator: SelectIntoOperator) -> Operator:
    operator.query_operator = optimize_query_operator(operator.query_operator)
    return operator
