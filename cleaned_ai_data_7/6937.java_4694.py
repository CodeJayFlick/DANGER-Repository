class RetypeLocalAction:
    def __init__(self):
        self.name = "Retype Variable"
        self.help_location = HelpLocation(HelpTopics.DECOMPILED, "ActionRetypeVariable")
        self.popup_menu_data = MenuData(["Retype Variable"], "Decompile")
        self.key_binding_data = KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK)

    def retype_symbol(self, program: Program, high_symbol: HighSymbol, exact_spot: Varnode, dt: DataType, tool: PluginTool):
        hfunction = high_symbol.get_high_function()

        commit_required = self.check_full_commit(high_symbol, hfunction)
        if commit_required:
            exact_spot = None  # Don't try to split out if commit is required

        if exact_spot is not None:  # The user pointed at a particular usage, not just the vardecl
            try:
                high_var = hfunction.split_out_merge_group(exact_spot.get_high(), exact_spot)
                high_symbol = high_var.get_symbol()
            except PcodeException as e:
                Msg.show_error(self, tool.get_tool_frame(), "Retype Failed", str(e))
                return

        data_type_manager = program.get_data_type_manager()

        successful_mod = False
        transaction = program.start_transaction("Retype Variable")
        try:
            if dt.get_data_type_manager() != data_type_manager:
                dt = data_type_manager.resolve(dt, None)

            if commit_required:
                # Don't use datatypes of other parameters if the datatypes were floating.
                # Datatypes were floating if signature source was DEFAULT
                use_datatype = hfunction.get_function().get_signature_source() != SourceType.DEFAULT

                try:
                    HighFunctionDBUtil.commit_params_to_database(hfunction, use_datatype, SourceType.USER_DEFINED)
                    if use_datatype:
                        HighFunctionDBUtil.commit_return_to_database(hfunction, SourceType.USER_DEFINED)

                except DuplicateNameException as e:
                    raise AssertionError("Unexpected exception", e)

                except InvalidInputException as e:
                    Msg.show_error(self, None, "Parameter Commit Failed", str(e))

            high_function_db_util.update_db_variable(high_symbol, None, dt, SourceType.USER_DEFINED)
            successful_mod = True

        except DuplicateNameException as e:
            raise AssertionError("Unexpected exception", e)

        except InvalidInputException as e:
            Msg.show_error(self, tool.get_tool_frame(), "Retype Failed",
                           f"Failed to re-type variable '{high_symbol.name}': {str(e)}")

        finally:
            program.end_transaction(transaction, successful_mod)

    def check_full_commit(self, high_symbol: HighSymbol, hfunction: HighFunction):
        return True  # Replace this with your actual logic

    @property
    def help_location(self) -> HelpLocation:
        return self._help_location

    @help_location.setter
    def help_location(self, value: HelpLocation):
        self._help_location = value

    @property
    def popup_menu_data(self) -> MenuData:
        return self._popup_menu_data

    @popup_menu_data.setter
    def popup_menu_data(self, value: MenuData):
        self._popup_menu_data = value

    @property
    def key_binding_data(self) -> KeyBindingData:
        return self._key_binding_data

    @key_binding_data.setter
    def key_binding_data(self, value: KeyBindingData):
        self._key_binding_data = value


class Program:
    pass  # Replace this with your actual implementation of the program class


class HighSymbol:
    pass  # Replace this with your actual implementation of the high symbol class


class Varnode:
    pass  # Replace this with your actual implementation of the varnode class


class DataTypeManager:
    def resolve(self, dt: DataType, null):
        return None  # Replace this with your actual logic for resolving data types

    def get_data_type_manager(self) -> 'DataTypeManager':
        return self
