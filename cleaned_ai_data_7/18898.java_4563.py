class CelAccessChecker:
    def __init__(self, config: 'QuarkusNessieAuthorizationConfig', compiled_rules):
        self.config = config
        self.compiled_rules = compiled_rules

    def can_view_reference(self, context, ref) -> None:
        self.can_perform_op_on_reference(context, ref, "VIEW_REFERENCE")

    def can_create_reference(self, context, ref) -> None:
        self.can_perform_op_on_reference(context, ref, "CREATE_REFERENCE")

    def can_assign_ref_to_hash(self, context, ref) -> None:
        self.can_view_reference(context, ref)
        self.can_perform_op_on_reference(context, ref, "ASSIGN_REFERENCE_TO_HASH")

    # ... (similar methods for other operations)

    def get_role_name(self, context):
        return "" if not context.user() else context.user().name

    def can_perform_op_on_reference(self, context, ref, op_type) -> None:
        if not self.config.enabled():
            return
        role_name = self.get_role_name(context)
        arguments = {"ref": ref.name, "role": role_name, "op": op_type}
        error_message_supplier = lambda: f"'{op_type}' is not allowed for role '{role_name}' on reference '{ref.name}'"
        self.can_perform_op(arguments, error_message_supplier)

    def can_perform_op_on_path(self, context, ref, contents_key, op_type) -> None:
        if not self.config.enabled():
            return
        role_name = self.get_role_name(context)
        arguments = {"ref": ref.name, "path": str(contents_key), "role": role_name, "op": op_type}
        error_message_supplier = lambda: f"'{op_type}' is not allowed for role '{role_name}' on content '{str(contents_key)}'"
        self.can_perform_op(arguments, error_message_supplier)

    def can_perform_op(self, arguments, error_message_supplier) -> None:
        if any(rule.execute([arguments], True) for rule in self.compiled_rules.get_rules()):
            return
        raise AccessControlException(error_message_supplier())
