Here is the translation of the given Java code into Python:

```Python
class DNFFilterOptimizer:
    def __init__(self):
        pass

    @staticmethod
    def optimize(filter_operator: 'FilterOperator') -> 'FilterOperator':
        return DNFFilterOptimizer.get_dnf(filter_operator)

    @staticmethod
    def get_and_child(child: 'FilterOperator') -> list:
        if child.filter_type == FilterType.KW_OR:
            return child.children
        else:
            return [child]

    @staticmethod
    def deal_with_left_and_right_and_children(left_and_children, right_and_children, new_children_list):
        for left_and_child in left_and_children:
            for right_and_child in right_and_children:
                r = DNFFilterOptimizer.merge_to_conjunction(left_and_child.copy(), right_and_child.copy())
                new_children_list.append(r)

    @staticmethod
    def merge_to_conjunction(operator1: 'FilterOperator', operator2: 'FilterOperator') -> 'FilterOperator':
        ret_children_list = []
        DNFFilterOptimizer.add_child_in_and(operator1, ret_children_list)
        DNFFilterOptimizer.add_child_in_and(operator2, ret_children_list)
        ret = FilterOperator(FilterType.KW_AND, False)
        ret.children = ret_children_list
        return ret

    @staticmethod
    def add_child_in_and(operator: 'FilterOperator', new_children_list):
        if operator.is_leaf:
            new_children_list.append(operator)
        elif operator.filter_type == FilterType.KW_AND:
            new_children_list.extend(operator.children)
        else:
            raise LogicalOptimizeException("add all children of an OR operator to newChildrenList in AND")

    @staticmethod
    def add_child_in_or(operator: 'FilterOperator', new_children_list):
        if operator.is_leaf or operator.filter_type == FilterType.KW_AND:
            new_children_list.append(operator)
        else:
            new_children_list.extend(operator.children)

    @staticmethod
    def get_dnf(filter_operator: 'FilterOperator') -> 'FilterOperator':
        if filter_operator.is_leaf:
            return filter_operator

        child_operators = filter_operator.children
        if len(child_operators) != 2:
            raise LogicalOptimizeException(f"node {filter_operator.filter_name} has {len(child_operators)} children")

        left = DNFFilterOptimizer.get_dnf(child_operators[0])
        right = DNFFilterOptimizer.get_dnf(child_operators[1])

        new_children_list = []
        if filter_operator.filter_type == FilterType.KW_OR:
            DNFFilterOptimizer.add_child_in_or(left, new_children_list)
            DNFFilterOptimizer.add_child_in_or(right, new_children_list)
        elif filter_operator.filter_type == FilterType.KW_AND:
            if left.filter_type != FilterType.KW_OR and right.filter_type != FilterType.KW_OR:
                DNFFilterOptimizer.add_child_in_and(left, new_children_list)
                DNFFilterOptimizer.add_child_in_and(right, new_children_list)
            else:
                DNFFilterOptimizer.deal_with_left_and_right_and_children(DNFFilterOptimizer.get_and_child(left), DNFFilterOptimizer.get_and_child(right), new_children_list)
                filter_operator.filter_type = FilterType.KW_OR
        else:
            raise LogicalOptimizeException(f"get DNF failed, this token type is {filter_operator.filter_type}")

        filter_operator.children = new_children_list
        return filter_operator

class FilterOperator:
    def __init__(self, filter_type: int, is_leaf: bool):
        self.filter_type = filter_type
        self.is_leaf = is_leaf
        self.children = []

class LogicalOptimizeException(Exception):
    pass
```

Please note that this translation does not include the `FilterConstant` class or any other classes mentioned in your original code.