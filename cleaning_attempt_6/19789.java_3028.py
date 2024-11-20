class FunctionReference:
    def __init__(self, function_name: str, node: object = None, script: str = None, return_types: list[object] = None, parameters: tuple[Expression, ...]) -> None:
        self.function_name = functionName
        self.node = node
        self.script = script
        self.return_types = return_types if return_types else []
        self.parameters = parameters

    def validate_function(self) -> bool:
        previous_function = self.get_function()
        self.set_function(None)
        
        SkriptLogger.set_node(self.node)

        sign = Functions.get_signature(self.function_name)

        # Check if the requested function exists
        if sign is None:
            if first:
                Skript.error(f"The function '{self.function_name}' does not exist.")
            else:
                Skript.error(f"The function '{self.function_name}' was deleted or renamed, but is still used in other script(s). These will continue to use the old version of the function until Skript restarts.")
                self.set_function(previous_function)
            return False

        # Validate that return types are what caller expects they are
        if return_types:
            rt = sign.return_type
            if rt is None:
                if first:
                    Skript.error(f"The function '{self.function_name}' doesn't return any value.")
                else:
                    Skript.error(f"The function '{self.function_name}' was redefined with no return value, but is still used in other script(s). These will continue to use the old version of the function until Skript restarts.")
                    self.set_function(previous_function)
            if not CollectionUtils.contains_any_superclass(return_types, rt.get_c()):
                if first:
                    Skript.error(f"The returned value of the function '{self.function_name}', {sign.return_type}, is {SkriptParser.not_of_type(return_types)}.")
                else:
                    Skript.error(f"The function '{self.function_name}' was redefined with a different, incompatible return type, but is still used in other script(s). These will continue to use the old version of the function until Skript restarts.")
                    self.set_function(previous_function)
            if first:
                self.single = sign.single
            else:
                if self.single and not sign.single:
                    Skript.error(f"The function '{self.function_name}' was redefined with a different, incompatible return type, but is still used in other script(s). These will continue to use the old version of the function until Skript restarts.")
                    self.set_function(previous_function)

        # Validate parameter count
        if not sign.get_max_parameters() == 1 and not sign.get_parameter(0).single:
            if parameters.length > sign.get_max_parameters():
                if first:
                    if sign.get_max_parameters() == 0:
                        Skript.error(f"The function '{self.function_name}' has no arguments, but {parameters.length} are given.")
                        print("To call a function without parameters, just write the function name followed by '()', e.g. 'func()'.")
                else:
                    Skript.error(f"The function '{self.function_name}' was redefined with different, incompatible amount of arguments, but is still used in other script(s). These will continue to use the old version of the function until Skript restarts.")
                    self.set_function(previous_function)
            return False

        # Not enough parameters
        if parameters.length < sign.get_min_parameters():
            if first:
                Skript.error(f"The function '{self.function_name}' requires at least {sign.get_min_parameters()} argument{'s'}, but only {parameters.length} {'is' if parameters.length == 1 else 'are'} given.")
            else:
                Skript.error(f"The function '{self.function_name}' was redefined with different, incompatible amount of arguments, but is still used in other script(s). These will continue to use the old version of the function until Skript restarts.")
                self.set_function(previous_function)
            return False

        # Check parameter types
        for i, p in enumerate(parameters):
            if single_list_param and parameters.length > 1:
                l = []
                for e in parameters:
                    l.extend(e.get_array())
                params[0] = l.toarray()
            else:
                array = [p.get_array()]
                return False

    def get_function(self) -> object:
        return self.function

    def reset_return_value(self) -> bool:
        if self.function is not None:
            return self.function.reset_return_value()

    @staticmethod
    def execute(e: Event, params: list[object]) -> tuple[object]:
        # If needed, acquire the function reference
        if self.function is None:
            self.function = Functions.get_function(self.function_name)

        if self.function is None:
            Skript.error(f"Couldn't resolve call for '{self.function_name}'. Be careful when using functions in 'script load' events!")
            return None  # Return nothing and hope it works

    def is_single(self) -> bool:
        return single

    @staticmethod
    def get_return_type() -> object:
        if signature is None:
            raise SkriptAPIException("Signature of function is null when return type is asked!")

        ret = signature.return_type.get_c()
        return ret

    def __str__(self, e: Event, debug: bool) -> str:
        b = f"{self.function_name}("
        for i in range(len(self.parameters)):
            if i != 0:
                b += ", "
            b += self.parameters[i].__str__(e, debug)
        b += ")"
        return b
