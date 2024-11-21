class GhidraDataTypeArchiveMergeManagerFactory:
    def do_merge_manager(self, results_obj, source_obj, original_obj, latest_obj):
        return DataTypeArchiveMergeManager(
            self.convert_domain_object(results_obj), 
            self.convert_domain_object(source_obj), 
            self.convert_domain_object(original_obj), 
            self.convert_domain_object(latest_obj), 
            ((latest_obj).get_changes()), 
            ((source_obj).get_changes())
        )

    def convert_domain_object(self, obj):
        return DataTypeManagerDomainObject(obj)

class DataTypeArchiveMergeManager:
    def __init__(self, results_obj, source_obj, original_obj, latest_obj, changes1, changes2):
        self.results_obj = results_obj
        self.source_obj = source_obj
        self.original_obj = original_obj
        self.latest_obj = latest_obj
        self.changes1 = changes1
        self.changes2 = changes2

class DataTypeManagerDomainObject:
    def __init__(self, obj):
        self.obj = obj

    def get_changes(self):
        return ((self.obj).get_changes())

# Example usage:
factory = GhidraDataTypeArchiveMergeManagerFactory()
merge_manager = factory.do_merge_manager(results_obj, source_obj, original_obj, latest_obj)
