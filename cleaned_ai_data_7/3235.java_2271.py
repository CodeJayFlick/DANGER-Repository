class CreateFolderCommand:
    def __init__(self, tree_name: str, name: str, parent_name: str):
        self.tree_name = tree_name
        self.name = name
        self.parent_name = parent_name
        self.status_msg = ""

    def apply_to(self, obj) -> bool:
        program = obj  # Assuming 'obj' is a Program object in Python
        listing = program.get_listing()
        module = listing.get_module(self.tree_name, self.parent_name)
        
        if module is None:
            self.status_msg = f"Folder named {self.parent_name} does not exist"
            return False
        
        try:
            module.create_module(self.name)  # Assuming 'module' has a method create_module
            return True
        except Exception as e:  # Assuming DuplicateNameException in Python is raised by some other exception
            self.status_msg = f"{self.name} already exists"
        
        return False

    def get_status_msg(self):
        return self.status_msg

    def get_name(self) -> str:
        return "Create Folder"


# Example usage:

if __name__ == "__main__":
    command = CreateFolderCommand("tree_name", "folder_name", "parent_folder")
    
    # Assuming 'program' is a Program object in Python
    if not command.apply_to(program):
        print(command.get_status_msg())
