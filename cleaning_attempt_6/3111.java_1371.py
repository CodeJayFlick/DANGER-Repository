class SearchMnemonicsNoOpsNoConstScript:
    def run(self):
        self.set_state(SLMaskControl(True, False, False, False))
        self.load_selected_instructions()
        self.execute_search()

# Define a class for SLMaskControl
class SLMaskControl:
    def __init__(self, mask_control1, mask_control2, mask_control3, mask_control4):
        self.mask_control1 = mask_control1
        self.mask_control2 = mask_control2
        self.mask_control3 = mask_control3
        self.mask_control4 = mask_control4

# Define a class for SearchBaseExtended (assuming it's equivalent to Python's object)
class SearchBaseExtended:
    def __init__(self):
        pass

    # Assuming setState is defined elsewhere, this method sets the state of an instance.
    def set_state(self, state):
        self.state = state
