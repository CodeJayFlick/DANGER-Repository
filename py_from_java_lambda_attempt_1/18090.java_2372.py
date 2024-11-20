Here is the translation of the given Java code into Python:

```Python
class MergeSingleFilterOptimizer:
    def optimize(self, filter):
        self.merge_same_path_filter(filter)
        return filter

    @staticmethod
    def merge_same_path_filter(filter):
        if not filter.is_leaf():
            children = filter.get_children()
            if len(children) == 0:
                raise MergeFilterException("this inner filter has no children!")
            elif len(children) == 1:
                raise MergeFilterException("this inner filter has just one child!")

            child_path = self.merge_same_path_filter(children[0])
            temp_path = None
            for i in range(1, len(children)):
                temp_path = self.merge_same_path_filter(children[i])
                if temp_path is None or not temp_path == child_path:
                    child_path = None

            if child_path is not None:
                filter.set_is_single(True)
                filter.set_single_path(child_path)
                return child_path
        else:
            return filter.get_single_path()

        # make same paths close
        children.sort()
        ret = []
        temp_extr_node = None
        for i in range(len(children)):
            path = children[i].get_single_path()
            if path is None:
                break

            if child_path is None:
                child_path = path
                temp_extr_node = [children[i]]
            elif path == child_path:
                temp_extr_node.append(children[i])
            else:
                # not more same, add exist nodes in tempExtrNode into a new node
                # prevent make a node which has only one child.
                if len(temp_extr_node) == 1:
                    ret.append(temp_extr_node[0])
                    temp_extr_node[0] = children[i]
                    child_path = path
                else:
                    # add a new inner node
                    filter_operator = FilterOperator(filter.get_token_int_type(), True)
                    filter_operator.set_single_path(child_path)
                    filter_operator.set_children_list(temp_extr_node)
                    ret.append(filter_operator)
                    temp_extr_node = [children[i]]
                    child_path = path

        if child_path is not None:
            if len(temp_extr_node) == 1:
                ret.append(temp_extr_node[0])
            else:
                # add a new inner node
                filter_operator = FilterOperator(filter.get_token_int_type(), True)
                filter_operator.set_single_path(child_path)
                filter_operator.set_children_list(temp_extr_node)
                ret.append(filter_operator)

        for i in range(len(children)):
            if children[i].get_single_path() is None:
                break

        # add last null children
        for _ in range(i, len(children)):
            ret.append(children[_])

        if len(ret) == 1:
            filter.set_is_single(True)
            filter.set_single_path(child_path)
            filter.set_children_list([ret[0]])
            return child_path
        else:
            filter.set_is_single(False)
            filter.set_children_list(ret)
            return None

    @staticmethod
    def all_is_basic(children):
        for child in children:
            if not isinstance(child, BasicOperator):
                return False
        return True


class FilterOperator:
    def __init__(self, token_int_type, is_leaf):
        self.token_int_type = token_int_type
        self.is_leaf = is_leaf

    def get_children(self):
        # implement this method to return the children of the filter operator
        pass

    def set_is_single(self, value):
        self.is_single = value

    def set_single_path(self, path):
        self.single_path = path

    def set_children_list(self, children):
        self.children = children


class MergeFilterException(Exception):
    pass
```

Note that the `get_children()` method in the `FilterOperator` class is not implemented. You would need to implement this based on your specific use case and data structure.