class FilterOperator:
    def __init__(self, token_type):
        self.token_type = token_type
        self.child_operators = []
        self.is_leaf = False
        self.is_single = False
        self.single_path = None

    def set_token_int_type(self, int_type):
        self.token_int_type = int_type
        self.token_symbol = SQLConstant.get_token_symbol(int_type)

    def add_head_delta_object_path(self, delta_object):
        for child in self.child_operators:
            child.add_head_delta_object_path(delta_object)
        if self.is_single:
            self.single_path = f"{delta_object}.{self.single_path}"

    @property
    def children(self):
        return self.child_operators

    def get_all_paths(self):
        paths = []
        if self.is_leaf:
            paths.append(self.single_path)
        else:
            for child in self.child_operators:
                paths.extend(child.get_all_paths())
        return paths

    @property
    def is_single_(self):
        return self.is_single

    @is_single_.setter
    def set_is_single_(self, value):
        self.is_single = value

    @property
    def single_path_(self):
        return self.single_path_

    @single_path_.setter
    def set_single_path_(self, value):
        self.single_path_ = value

    def add_child_operator(self, op):
        self.child_operators.append(op)

    def __eq__(self, other):
        if not isinstance(other, FilterOperator):
            return NotImplemented
        if self.single_path is None and other.single_path is None:
            return True
        elif self.single_path is None:
            return False
        elif other.single_path is None:
            return False
        else:
            return self.single_path == other.single_path

    def __lt__(self, other):
        if not isinstance(other, FilterOperator):
            return NotImplemented
        if self.single_path is None and other.single_path is None:
            return 0
        elif self.single_path is None:
            return -1
        elif other.single_path is None:
            return 1
        else:
            return self.single_path < other.single_path

    def __str__(self):
        sc = StringContainer()
        sc.add_tail(f"[{self.token_symbol}", f"{self.get_single_path() if self.is_single else ''}]")
        for child in self.child_operators:
            sc.add_tail(child.__str__())
        return sc.__str__()

    def clone(self):
        ret = FilterOperator(self.token_int_type)
        ret.token_symbol = self.token_symbol
        ret.is_leaf = self.is_leaf
        ret.is_single = self.is_single
        if self.single_path is not None:
            ret.single_path_ = self.single_path_
        for child in self.child_operators:
            ret.add_child_operator(child.clone())
        return ret

class StringContainer:
    def __init__(self):
        self.string_container = ""

    def add_tail(self, *args):
        self.string_container += "".join(map(str, args)) + " "

    @property
    def string_(self):
        return self.string_

    @string_.setter
    def set_string_(self, value):
        self.string_ = value

    def __str__(self):
        return f"[{self.string_}]"
