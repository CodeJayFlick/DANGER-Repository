Here is the translation of the Java code into Python:

```Python
class DNFFilterOptimizer:
    def __init__(self):
        pass

    @staticmethod
    def optimize(filter_operator: 'FilterOperator') -> 'FilterOperator':
        return filter_operator.get_dnf()

    @staticmethod
    def get_dnf(filter_operator: 'FilterOperator') -> 'FilterOperator':
        if filter_operator.is_leaf():
            return filter_operator
        
        children = filter_operator.children()
        
        if len(children) != 2:
            raise DNFOptimizeException(f"node {filter_operator.get_token_symbol()} has {len(children)} children")
        
        left_child, right_child = children
        new_children_list = []
        
        token_type = filter_operator.get_token_int_type()
        
        if token_type == KW_OR:
            DNFFilterOptimizer.add_child_op_in_or(left_child, new_children_list)
            DNFFilterOptimizer.add_child_op_in_or(right_child, new_children_list)
        elif token_type == KW_AND:
            left_and_children = get_and_child(left_child)
            right_and_children = get_and_child(right_child)
            
            for la_child in left_and_children:
                for ra_child in right_and_children:
                    r = DNFFilterOptimizer.merge_to_conjunction(la_child, ra_child)
                    new_children_list.append(r)
            
            filter_operator.set_token_int_type(KW_OR)
        else:
            raise DNFOptimizeException(f"get DNF failed, this tokenType is: {filter_operator.get_token_int_type()}")
        
        filter_operator.set_children(new_children_list)
        return filter_operator

    @staticmethod
    def merge_to_conjunction(a: 'FilterOperator', b: 'FilterOperator') -> 'FilterOperator':
        ret_children_list = []
        DNFFilterOptimizer.add_child_op_in_and(a, ret_children_list)
        DNFFilterOptimizer.add_child_op_in_and(b, ret_children_list)
        
        ret = FilterOperator(KW_AND, False)
        ret.set_children(ret_children_list)
        return ret

    @staticmethod
    def get_and_child(child: 'FilterOperator') -> list:
        token_type = child.get_token_int_type()
        
        if token_type == KW_OR:
            return child.children()
        else:
            # other token type means leaf node or "and" operator
            return [child]

    @staticmethod
    def add_child_op_in_and(child: 'FilterOperator', new_children_list: list) -> None:
        if child.is_leaf():
            new_children_list.append(child)
        elif child.get_token_int_type() == KW_AND:
            new_children_list.extend(child.children())
        else:
            raise DNFOptimizeException("add all children of an OR operator to newChildrenList in AND")

    @staticmethod
    def add_child_op_in_or(child: 'FilterOperator', new_children_list: list) -> None:
        if child.is_leaf() or child.get_token_int_type() == KW_AND:
            new_children_list.append(child)
        else:
            new_children_list.extend(child.children())

class FilterOperator:
    pass

class DNFOptimizeException(Exception):
    pass
```

Please note that this translation is not a direct copy-paste, but rather an equivalent Python code. The original Java code might have some specific features or libraries that are not directly translatable to Python.