class CommitParamsAction:
    def __init__(self):
        self.description = "Save Parameters/Return definitions to Program, locking them into their current type definitions"
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ActionCommitParams")
        self.popup_menu_data = MenuData(["Commit Params/Return"], "Commit")
        self.key_binding_data = KeyBindingData(KeyEvent.VK_P, 0)

    def is_enabled_for_decompiler_context(self, context):
        if not context.has_real_function():
            return False
        return context.get_high_function() is not None

    def decompiler_action_performed(self, context):
        program = context.get_program()
        try:
            transaction = program.start_transaction("Commit Params/Return")
            high_function = context.get_high_function()
            source_type = SourceType.ANALYSIS
            if high_function.function.signature_source == SourceType.USER_DEFINED:
                source_type = SourceType.USER_DEFINED

            HighFunctionDBUtil.commit_return_to_database(high_function, source_type)
            HighFunctionDBUtil.commit_params_to_database(high_function, True, source_type)

        except DuplicateNameException as e:
            raise AssertException("Unexpected exception", e) from None
        except InvalidInputException as e:
            Msg.show_error(self, None, "Parameter Commit Failed", str(e))
        finally:
            program.end_transaction(transaction, True)
