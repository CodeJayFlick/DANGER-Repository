class TernaryExpression:
    def __init__(self):
        self.source = None
        self.super_type = object
        self.types = [object]
    
    @property
    def if_true(self):
        return self._if_true
    
    @if_true.setter
    def if_true(self, value):
        self._if_true = value
    
    @property
    def if_false(self):
        return self._if_false
    
    @if_false.setter
    def if_false(self, value):
        self._if_false = value
    
    @property
    def condition(self):
        return self._condition
    
    @condition.setter
    def condition(self, value):
        self._condition = value

def init(exprs, matched_pattern, is_delayed, parse_result):
    try:
        if_true_expr = exprs[0]
        if_false_expr = exprs[1]
        
        if isinstance(if_false_expr, TernaryExpression) or isinstance(if_true_expr, TernaryExpression):
            raise ValueError("Ternary operators may not be nested!")
        
        cond_str = parse_result.regexes[0].group()
        condition = Condition.parse(cond_str)
        
        return condition is not None and LiteralUtils.can_init_safely(if_true_expr, if_false_expr)

def get(event):
    values = condition.check(event) and if_true_expr.get_array(event) or if_false_expr.get_array(event)
    
    try:
        converted_values = Converters.convert_array(values, types, super_type)
        
        return [converted_value for converted_value in converted_values]
    except ClassCastException as e1:
        return []

def get_converted_expression(to):
    return TernaryExpression(self, to)

def get_source():
    if source is None:
        return self
    else:
        return source

def get_return_type():
    return super_type

def is_single():
    return if_true_expr.is_single() and if_false_expr.is_single()

def __str__(self):
    return f"{if_true_expr} if {condition} otherwise {if_false_expr}"
