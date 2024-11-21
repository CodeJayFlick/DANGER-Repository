class WrapIDynamicConceptProviderConcept:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def get_concept(self, context_object, concept_id, concept_interface=None, concept_metadata=None, has_concept=False):
        return self._invoke_hr(1, self.get_pointer(), context_object, concept_id, concept_interface, concept_metadata, has_concept)

    def set_concept(self, context_object, concept_id, concept_interface, concept_metadata):
        return self._invoke_hr(2, self.get_pointer(), context_object, concept_id, concept_interface, concept_metadata)

    def notify_parent(self, parent_model):
        return self._invoke_hr(3, self.get_pointer(), parent_model)

    def notify_parent_change(self, parent_model):
        return self._invoke_hr(4, self.get_pointer(), parent_model)

    def notify_destruct(self):
        return self._invoke_hr(5, self.get_pointer())

class ByReference(WrapIDynamicConceptProviderConcept):
    pass

def _invoke_hr(index, pointer, *args):
    # implement the logic for invoking HR
    pass
