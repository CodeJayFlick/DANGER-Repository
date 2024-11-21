class MergeFolderCmd:
    def __init__(self, tree_name: str, folder_name: str, parent_name: str):
        self.tree_name = tree_name
        self.folder_name = folder_name
        self.parent_name = parent_name

    def apply_to(self, obj) -> bool:
        program = obj.get_program()
        listing = program.get_listing()

        try:
            parent_module = listing.get_module(tree_name, parent_name)
            module = listing.get_module(tree_name, folder_name)

            if not (parent_module and module):
                return True  # ignore since the tree has changed since this command was scheduled

            groups = module.get_children()
            for i in range(len(groups)):
                name = groups[i].get_name()

                try:
                    m = listing.get_module(tree_name, name)
                    f = None
                    if m and parent_module.contains(m):
                        module.remove_child(name)
                        continue
                    elif not m:
                        f = listing.get_fragment(tree_name, name)
                        if parent_module.contains(f):
                            module.remove_child(name)
                            continue

                except Exception as e:
                    print("Error merging folder with its parent")
                    return False

                try:
                    parent_module.reparent(name, module)
                except Exception as e:
                    print("Error merging folder with its parent")

            # now remove the module from its parent...
            m = listing.get_module(tree_name, folder_name)
            parents = m.get_parents()
            for i in range(len(parents)):
                try:
                    parents[i].remove_child(folder_name)
                except Exception as e:
                    self.err_msg = str(e)

        except Exception as e:
            print("Error merging folder with its parent")
            return False

    def get_status_msg(self) -> str:
        if hasattr(self, 'err_msg'):
            return self.err_msg
        else:
            return "Folder merged successfully"

    def get_name(self) -> str:
        return f"Merge {self.folder_name} with Parent"
