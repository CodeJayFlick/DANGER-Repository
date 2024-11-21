class PdbCategories:
    def __init__(self, pdb_category_name: str, module_names: list):
        if not pdb_category_name:
            raise ValueError("pdbCategoryName cannot be null")
        
        self.pdb_root_category = CategoryPath(CategoryPath.ROOT, pdb_category_name)
        self.pdb_uncategorized_category = CategoryPath(self.pdb_root_category, "_UNCATEGORIZED_")

        self.set_typedef_category_paths(module_names)

        self.anonymous_functions_category = CategoryPath(self.pdb_root_category, "!_anon_funcs_")
        # self.anonymous_function_count = 0

        self.anonymous_types_category = CategoryPath(self.pdb_root_category, "!_anon_types_")

    def get_root_category_path(self) -> 'CategoryPath':
        return self.pdb_root_category

    def get_uncategorized_category_path(self) -> 'CategoryPath':
        return self.pdb_uncategorized_category

    def set_typedef_category_paths(self, module_names: list):
        self.base_module_typedefs_category = CategoryPath(self.pdb_root_category, "!_module_typedefs_")
        # non-module typedefs go with all other global types, not in
        #  baseModuleTypedefsCategory.
        self.typedef_categories.append(self.pdb_root_category)
        for name in module_names:
            category_path = CategoryPath(self.base_module_typedefs_category, name) if name else self.base_module_typedefs_category
            self.typedef_categories.append(category_path)

    def get_category(self, symbol_path: 'SymbolPath') -> 'CategoryPath':
        category = self.pdb_root_category

        if not symbol_path:
            return category  # global namespace

        return self.recurse_get_category_path(category, symbol_path)

    def recurse_get_category_path(self, category: 'CategoryPath', symbol_path: 'SymbolPath') -> 'CategoryPath':
        parent = symbol_path.get_parent()
        if parent is not None:
            category = self.recurse_get_category_path(category, parent)
        return CategoryPath(category, symbol_path.get_name())

    def get_typedefs_category(self, module_number: int, symbol_path: 'SymbolPath') -> 'CategoryPath':
        category = None
        if 0 <= module_number < len(self.typedef_categories):
            category = self.typedef_categories[module_number]
        else:
            # non-module typedefs go with all other global types, not in
            #  baseModuleTypedefsCategory.
            category = self.pdb_root_category

        if symbol_path is None:  # global namespace
            return category

        return self.recurse_get_category_path(category, symbol_path)

    def get_anonymous_functions_category(self) -> 'CategoryPath':
        return self.anonymous_functions_category

    def get_anonymous_types_category(self) -> 'CategoryPath':
        return self.anonymous_types_category


class CategoryPath:
    ROOT = "ROOT"

    def __init__(self, parent: str, name: str):
        self.parent = parent
        self.name = name

    @property
    def full_path(self) -> str:
        if not self.parent or self.parent == CategoryPath.ROOT:
            return self.name
        else:
            return f"{self.parent}/{self.name}"


class SymbolPath:
    DELIMITER = "_"

    def __init__(self, parent: 'SymbolPath', name: str):
        self.parent = parent
        self.name = name

    @property
    def get_parent(self) -> 'SymbolPath':
        return self if not self.parent else self.parent


# Usage example:
pdb_categories = PdbCategories("PDB", ["Module1", "Module2"])
print(pdb_categories.get_root_category_path().full_path)
