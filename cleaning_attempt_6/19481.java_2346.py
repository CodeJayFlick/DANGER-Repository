class PropertyExpression(F, T):
    def __init__(self):
        self.expr = None
    
    @staticmethod
    def register(c, type, property, from_type):
        Skript.register_expression(c, type, 'PROPERTY', f"[the] {property} of %{from_type}%", f"%{from_type}'[s] {property}")
    
    def set_expr(self, expr):
        self.expr = expr
    
    @property
    def get_expr(self):
        return self.expr
    
    def get(self, e):
        return self.get(e, self.expr.get_array(e))
    
    def get_all(self, e):
        return self.get(e, self.expr.get_all(e))
    
    def get(self, e, source):
        # Abstract method implementation
        pass
    
    def get(self, source, converter):
        assert source is not None and converter is not None
        return Converters.convert_unsafe(source, self.get_return_type(), converter)
    
    @property
    def is_single(self):
        return self.expr.is_single()
    
    @property
    def get_and(self):
        return self.expr.get_and()
    
    def simplify(self):
        self.expr = self.expr.simplify()
        return self

class Skript:
    @staticmethod
    def register_expression(c, type, expression_type, pattern1, pattern2):
        pass
    
    @staticmethod
    def get_return_type():
        # Abstract method implementation
        pass

class Converters:
    @staticmethod
    def convert_unsafe(source, target_type, converter):
        # Abstract method implementation
        pass
