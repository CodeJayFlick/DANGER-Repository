class EditRefTypeCmd:
    def __init__(self, ref: 'Reference', new_ref_type: 'RefType'):
        self.ref = ref
        self.new_ref_type = new_ref_type

    def apply_to(self, obj):
        if isinstance(obj, Program):
            ref_mgr = obj.get_reference_manager()
            ref = ref_mgr.update_ref_type(ref, self.new_ref_type)
            return True
        return False

    def get_status_msg(self):
        return ""

    def get_name(self):
        return "Edit Reference Type"
