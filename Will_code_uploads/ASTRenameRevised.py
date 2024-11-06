import ast
import astor
import re

class RenameTransformer(ast.NodeTransformer):
    def __init__(self):
        self.class_counter = 1
        self.func_counter = 1
        self.var_counter = 1
        self.param_counter = 1
        self.var_map = {}
        self.func_map = {}
        self.param_map = {}

    def visit_ClassDef(self, node):
        node.name = f"Class{self.class_counter}"
        self.class_counter += 1
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.name not in self.func_map:
            self.func_map[node.name] = f"Method{self.func_counter}"
            self.func_counter += 1
        node.name = self.func_map[node.name]

        for param in node.args.args:
            if param.arg not in self.param_map:
                self.param_map[param.arg] = f"Parameter{self.param_counter}"
                self.param_counter += 1
            param.arg = self.param_map[param.arg]

        return self.generic_visit(node)

    def visit_Call(self, node):
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id in self.func_map:
            node.func.id = self.func_map[node.func.id]
        elif isinstance(node.func, ast.Attribute) and node.func.attr in self.func_map:
            node.func.attr = self.func_map[node.func.attr]
        return node

    def visit_Assign(self, node):
        node.value = self.visit(node.value)
        for target in node.targets:
            self.visit(target)
        return node

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            if node.id not in self.var_map:
                self.var_map[node.id] = f"Variable{self.var_counter}"
                self.var_counter += 1
            node.id = self.var_map[node.id]
        elif isinstance(node.ctx, ast.Load):
            if node.id in self.var_map:
                node.id = self.var_map[node.id]
            elif node.id in self.param_map:
                node.id = self.param_map[node.id]
        return node

# final one pass method
def replace_using_map(code, repl_map):
    for key, val in repl_map.items():
        code = re.sub(r'\b' + re.escape(key) + r'\b', val, code)
    return code

# Read file, need to make general case just a for each
with open("ex1.py", "r") as file:
    source_code = file.read()

# Parse and transform the AST
tree = ast.parse(source_code)
transformer = RenameTransformer()
transformed_tree = transformer.visit(tree)
new_code = astor.to_source(transformed_tree)

# Manual one pass at end to clean up
new_code = replace_using_map(new_code, transformer.func_map)
new_code = replace_using_map(new_code, transformer.var_map)
new_code = replace_using_map(new_code, transformer.param_map)

# Creating the new file, need to work out making it in general case
with open("renamed_ex3.py", "w") as file:
    file.write(new_code)

print("Renaming complete!")
