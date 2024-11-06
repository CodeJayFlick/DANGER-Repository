import ast
import astor

class RenameTransformer(ast.NodeTransformer):
    def __init__(self):
        self.class_counter = 1
        self.func_counter = 1
        self.var_counter = 1
        self.var_map = {}
        self.func_map = {}

    def visit_ClassDef(self, node):
        node.name = f"Class{self.class_counter}"
        self.class_counter += 1
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.name not in self.func_map:
            self.func_map[node.name] = f"Method{self.func_counter}"
            self.func_counter += 1
        node.name = self.func_map[node.name]
        self.generic_visit(node)
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
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
        if isinstance(node.ctx, ast.Store) and node.id not in self.var_map:
            self.var_map[node.id] = f"Variable{self.var_counter}"
            self.var_counter += 1
        if node.id in self.var_map:
            node.id = self.var_map[node.id]
        return node

# Read the Python file
with open("ex1.py", "r") as file:
    source_code = file.read()

tree = ast.parse(source_code)
transformer = RenameTransformer()
transformed_tree = transformer.visit(tree)

new_code = astor.to_source(transformed_tree)
with open("renamed_ex1.py", "w") as file:
    file.write(new_code)

print("Renaming complete!")
