class ShowComponentPathAction:
    ACTION_NAME = "Show Component Path"
    GROUP_NAME = "BASIC_ACTION_GROUP"
    DESCRIPTION = f"Show the category for the selected component's data type"

    def __init__(self, provider):
        self.provider = provider

    def actionPerformed(self, context):
        message = ""
        index = 0
        dtc = None
        if hasattr(context.model, 'getMinIndexSelected'):
            index = getattr(context.model, 'getMinIndexSelected')()
        else:
            print("Error: getMinIndexSelected not found")
        
        try:
            dtc = context.model.get_component(index)
        except Exception as e:
            print(f"Error getting component: {e}")

        if dtc is not None:
            dt = dtc.data_type
            message = f"{dt.display_name} is in category '{dt.category_path.path}'."

        try:
            setattr(context.model, 'status', (message, False))
        except Exception as e:
            print(f"Error setting status: {e}")

        self.request_table_focus()

    def adjust_enablement(self):
        if hasattr(self.provider.model, 'is_single_component_row_selection'):
            return getattr(self.provider.model, 'is_single_component_row_selection')()
        else:
            print("Error: is_single_component_row_selection not found")
