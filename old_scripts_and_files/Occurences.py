import ast
from collections import defaultdict

class NameCollector(ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.occurrences = defaultdict(int)

    def visit_Name(self, node):
        self.occurrences[node.id] += 1
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.occurrences[node.name] += 1
        self.generic_visit(node)

    def visit_Assign(self, node):
        for match in node.targets:
            if isinstance(match, ast.Name):
                self.occurrences[match.id] += 1
        self.generic_visit(node)

def collectOccurrences(code):
    tree = ast.parse(code)
    collector = NameCollector()
    collector.visit(tree)
    return dict(collector.occurrences)

# Read Input file.
import os
os.chdir("Tobias_code_uploads")
inputFile = "AI_binarysearchtree.py"
with open(inputFile) as fileContent:
    code = fileContent.read()

# Display Dict of Occurences
occurrences = collectOccurrences(code)
print("Occurrences:", occurrences)

# Write Dict of Occurences to Output file.
file = open("AI_binaryseachtree_Output.json", 'a')
file.write(str(occurrences)) 
file.close
