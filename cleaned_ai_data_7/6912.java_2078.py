import ghidra_plugin_core.decompile.actions as actions
from ghidra_plugin_core import decompiler_action_context as dec_ctx
from ghidra_plugin_core.navigatable_action_context import NavigatableActionContext
from ghidra_plugin_core.location_references_service import LocationReferencesService

class FindReferencesToAddressAction(actions.AbstractFindReferencesToAddressAction):
    def __init__(self, tool, owner):
        super().__init__(tool, owner)
        self.set_help_location("ActionShowReferences", "DECOMPILER")
        self.set_popup_menu_data([LocationReferencesService.MENU_GROUP, self.name])

    def get_location(self, context: NavigatableActionContext) -> actions.ProgramLocation:
        if not isinstance(context, dec_ctx.DecompilerActionContext):
            return None
        return context.get_location()

    def is_enabled_for_context(self, context: actions.ActionContext) -> bool:
        if not isinstance(context, dec_ctx.DecompilerActionContext):
            return False

        decompiler_context = dec_ctx.DecompilerActionContext(context)
        return decompiler_context.check_action_enablement(lambda: super().is_enabled_for_context(context))

    def action_performed(self, context: actions.ActionContext) -> None:
        decompiler_context = dec_ctx.DecompilerActionContext(context)
        decompiler_context.perform_action(lambda: super().action_performed(context))
