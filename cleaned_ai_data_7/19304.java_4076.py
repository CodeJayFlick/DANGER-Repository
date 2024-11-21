class EntryValidator:
    def __init__(self):
        self.setter = None
    
    def set_setter(self, setter: 'Setter[str]'):
        self.setter = setter
    
    def validate(self, node) -> bool:
        if not isinstance(node, Node):
            self.not_an_entry_error(node)
            return False
        
        if self.setter is not None:
            self.setter.set((node).get_value())
        
        return True
    
    @staticmethod
    def not_an_entry_error(node: 'Node', separator='') -> None:
        EntryValidator._set_node(node)
        Skript.error(f"'{node.get_key()}' is not an entry (like '{separator}')")
    
    @classmethod
    def _set_node(cls, node) -> None:
        cls.set_node = staticmethod(lambda: node)

class Node:
    pass

class Setter:
    def set(self, value):
        # Your setter logic here
        pass

# Usage example:

def main():
    entry_validator = EntryValidator()
    
    if not entry_validator.validate(Node()):
        print("Validation failed")

if __name__ == "__main__":
    main()

