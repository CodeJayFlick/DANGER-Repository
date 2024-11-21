class AnalyzeStackRefsAction:
    def __init__(self, func_plugin):
        self.func_plugin = func_plugin
        super().__init__("Analyze Function Stack References", func_plugin.name)

        menu_bar_data = {"Analysis": ["Analyze Stack"]}
        set_menu_bar_data(menu_bar_data)
        
        popup_menu_data = {"Function": ["Analyze Stack"], "Stack": []}
        set_popup_menu_data(popup_menu_data)

    def actionPerformed(self, context):
        iter = self.func_plugin.get_functions(context)
        if not iter:
            message = "No function at current location"
            selection = context.selection
            if selection is not None:
                message = "No functions within current selection"

            self.func_plugin.tool.set_status_info("Analyze Stack: {}".format(message))
            return

        func_set = set()
        for func in iter:
            func_set.add(func.entry_point)

    def get_options(self, program):
        options = {}
        if not hasattr(program.options, "get"):
            return None
        analysis_properties = program.get_analysis_properties()
        stack_options = analysis_properties.get("Stack")
        
        # TODO: THIS MAY NOT BE THE BEST WAY TO get the options to agree with the analysis options!  Advise.
        use_new_stack_analysis = True
        create_local_variables = True
        create_param_variables = True

        if hasattr(stack_options, "register_option"):
            stack_options.register_option("Use General Stack Reference Propogator", 
                                          use_new_stack_analysis, None,
                                          "This works best on most processors")
            
            stack_options.register_option("Create Local Variables", create_local_variables, None,
                                          "Create Function Local stack variables and references")

            stack_options.register_option("Create Param Variables", create_param_variables, None,
                                          "Create Function Parameter stack variables and references")

        return options

    def execute(self, program):
        if self.get_options(program).get_boolean("Use General Stack Reference Propogator"):
            cmd = NewFunctionStackAnalysisCmd(set(), True)
        else:
            cmd = FunctionStackAnalysisCmd(set(), True)

        self.func_plugin.execute(program, cmd)


class ListingContextAction:
    def __init__(self):
        pass

    @abstractmethod
    def actionPerformed(self, context):
        pass


def main():
    func_plugin = None  # This should be replaced with the actual function plugin.
    
    action = AnalyzeStackRefsAction(func_plugin)
    return action


if __name__ == "__main__":
    main()
