class QueryProcessor:
    def generate_plans(self, filter_operator: FilterOperator, paths: list[str], column_names: list[str], ts_file_sequence_reader: TsFileSequenceReader, start: int, end: int) -> list[TSQueryPlan]:
        query_plans = []
        
        if filter_operator is not None:
            remove_not_optimizer = RemoveNotOptimizer()
            filter_operator = remove_not_optimizer.optimize(filter_operator)

            dnf_filter_optimizer = DNFFilterOptimizer()
            filter_operator = dnf_filter_optimizer.optimize(filter_operator)

            merge_single_filter_optimizer = MergeSingleFilterOptimizer()
            filter_operator = merge_single_filter_optimizer.optimize(filter_operator)

            filter_operators = self.split_filter(filter_operator)
            
            for filter_operator in filter_operators:
                single_query = self.construct_select_plan(filter_operator, column_names)
                if single_query is not None:
                    query_plans.extend(self.physical_optimizer.optimize(single_query, paths, ts_file_sequence_reader, start, end))
        
        else:
            query_plans.extend(self.physical_optimizer.optimize(None, paths, ts_file_sequence_reader, start, end))

        # merge query plan
        path_map = {}
        for query_plan in query_plans:
            if query_plan.get_paths() not in path_map:
                path_map[query_plan.get_paths()] = [query_plan]
            else:
                path_map[query_plan.get_paths()].append(query_plan)

        query_plans.clear()

        for plans in path_map.values():
            merge_plan = None
            for plan in plans:
                if merge_plan is None:
                    merge_plan = plan
                else:
                    time_filter_operator = FilterOperator(SQLConstant.KW_OR)
                    time_filter_children = [merge_plan.get_time_filter_operator(), plan.get_time_filter_operator()]
                    time_filter_operator.set_children_list(time_filter_children)
                    merge_plan.set_time_filter_operator(time_filter_operator)

                    value_filter_operator = FilterOperator(SQLConstant.KW_OR)
                    value_filter_children = [merge_plan.get_value_filter_operator(), plan.get_value_filter_operator()]
                    value_filter_operator.set_children_list(value_filter_children)
                    merge_plan.set_value_filter_operator(value_filter_operator)

            query_plans.append(merge_plan)

        return query_plans

    def split_filter(self, filter_operator: FilterOperator) -> list[FilterOperator]:
        if not filter_operator.is_single() or filter_operator.get_token_int_type() != SQLConstant.KW_OR:
            return [filter_operator]
        
        # a list of conjunctions linked by or
        return filter_operator.child_operators

    def construct_select_plan(self, filter_operator: FilterOperator, column_names: list[str]) -> SingleQuery | None:
        time_filter = None
        value_filter = None
        column_filter_operators = []

        single_filter_list = []
        
        if filter_operator.is_single():
            single_filter_list = [filter_operator]
        
        elif filter_operator.get_token_int_type() == SQLConstant.KW_AND:
            # original query plan has been dealt with merge optimizer, thus all nodes with same
            # path have been merged to one node
            single_filter_list = filter_operator.children

        if not single_filter_list:
            return None
        
        value_list = []
        for child in single_filter_list:
            if not child.is_single():
                value_list.append(child)
            else:
                single_path = child.get_single_path()
                if column_names.contains(single_path):
                    if not column_filter_operators.contains(child):
                        column_filter_operators.add(child)
                    else:
                        raise QueryOperatorException(f"The same key filter has been specified more than once: {single_path}")
                elif child.get_single_path() == SQLConstant.RESERVED_TIME:
                    if time_filter is None:
                        time_filter = child
                    else:
                        raise QueryOperatorException("time filter has been specified more than once")
                else:
                    value_list.append(child)

        if len(value_list) == 1:
            value_filter = value_list[0]
        
        elif len(value_list) > 1:
            value_filter = FilterOperator(SQLConstant.KW_AND, False)
            value_filter.children = value_list

        return SingleQuery(column_filter_operators, time_filter, value_filter)

    def physical_optimizer(self, column_names: list[str]) -> PhysicalOptimizer:
        pass
