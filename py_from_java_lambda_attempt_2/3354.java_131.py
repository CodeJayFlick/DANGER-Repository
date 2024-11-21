Here is the translation of the Java code into Python:

```Python
class ProgramMultiUserMergeManager:
    def __init__(self, result_program, my_program, original_program, latest_program, 
                 latest_change_set, my_change_set):
        self.result_domain_object = result_program
        self.my_domain_object = my_program
        self.original_domain_object = original_program
        self.latest_domain_object = latest_program

    def get_program(self, version):
        if version == 0:
            return self.result_domain_object
        elif version == 1:
            return self.my_domain_object
        elif version == 2:
            return self.original_domain_object
        elif version == 3:
            return self.latest_domain_object
        else:
            return None

    def create_merge_resolvers(self):
        merge_resolvers = []
        for i in range(8):
            if i == 0:
                merge_resolver = MemoryMergeManager(self, 
                                                     self.result_domain_object,
                                                     self.my_domain_object,
                                                     self.original_domain_object,
                                                     self.latest_domain_object)
            elif i == 1:
                merge_resolver = ProgramTreeMergeManager(self, 
                                                         self.result_domain_object,
                                                         self.my_domain_object,
                                                         self.original_domain_object,
                                                         self.latest_domain_object,
                                                         latest_change_set, my_change_set)
            # Add more resolvers as needed
        return merge_resolvers

    def show_default_merge_panel(self):
        pass  # Not implemented in Java either

    def initialize_merge(self):
        self.merge_panel = ListingMergePanel()
        self.navigatable = MergeNavigatable(self.merge_panel)

    def cleanup_merge(self):
        if hasattr(self, 'merge_panel'):
            self.merge_panel.dispose()

    def show_component(self, comp=None, component_id="", help_location=None):
        pass  # Not implemented in Java either

    def show_listing_merge_panel(self, result_address, latest_address, my_address, original_address):
        self.load_externals_into_merge_panel(result_address, 
                                             latest_address,
                                             my_address,
                                             original_address)

    def load_externals_into_merge_panel(self, result_address, 
                                        latest_address,
                                        my_address,
                                        original_address):
        pass  # Not implemented in Java either

    def remove_listing_merge_panel(self):
        if hasattr(self, 'merge_tool'):
            self.merge_tool.remove_plugins([self.listing_plugin, self.go_to_plugin])
            self.is_showing_listing_merge_panel = False
            self.show_default_component()

class MergeNavigatable:
    def __init__(self, merge_panel):
        self.merge_panel = merge_panel

    # Implement the rest of the methods as needed
```

Note that this is a direct translation from Java to Python and may not be perfect. Some parts might need adjustments or modifications based on your specific requirements.