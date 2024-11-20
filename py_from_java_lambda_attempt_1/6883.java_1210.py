Here is a translation of the provided Java code into equivalent Python:

```Python
class DecompilerCommentsActionFactory:
    def do_get_edit_comments_action(self, dialog: 'CommentsDialog', name: str) -> object:
        return DecompilerEditCommentsAction(dialog, name)

    def do_get_set_comments_action(self, dialog: 'CommentsDialog', name: str, action_name: str, comment_type: int) -> object:
        return DecompilerSetCommentsAction(dialog, name, action_name, comment_type)

    def do_is_comment_supported(self, loc: 'ProgramLocation') -> bool:
        if not loc or not loc.get_address():
            return False
        return isinstance(loc, (CodeUnitLocation, DecompilerLocation)) or \
               isinstance(loc, FunctionLocation) and not isinstance(loc, VariableLocation)


class DecompilerSetCommentsAction:
    def __init__(self, dialog: 'CommentsDialog', name: str, action_name: str, comment_type: int):
        self.dialog = dialog
        self.comment_type = comment_type
        super().__init__(action_name, name)
        self.set_popup_menu_data(['Comments', f'{action_name}...', 'comments'])
        self.set_help_location(HelpLocation('DECOMPILER', 'ActionComments'))

    def get_edit_comment_type(self) -> int:
        return self.comment_type

    def action_performed(self, context: object):
        cu = self.get_code_unit(context)
        type_ = self.get_edit_comment_type()
        self.dialog.show_dialog(cu, type_)

    def is_enabled_for_context(self, context: object) -> bool:
        loc = self.get_location_for_context(context)
        if not self.do_is_comment_supported(loc):
            return False
        return CommentType.is_allowed_to_comment(get_code_unit=context, location=loc)

    def is_valid_context(self, context: object) -> bool:
        return isinstance(context, (ListingActionContext, DecompilerActionContext))

    def get_code_unit(self, context: object) -> 'CodeUnit':
        if not isinstance(context, ProgramLocationActionContext):
            raise ValueError('Invalid Context')
        return context.get_code_unit()

    def get_location_for_context(self, context: object) -> 'ProgramLocation':
        if isinstance(context, DecompilerActionContext):
            if self.comment_type != CodeUnit.PRE_COMMENT and \
               self.comment_type != CodeUnit.PLATE_COMMENT and \
               self.comment_type != CodeUnit.NO_COMMENT:
                return None
        elif not isinstance(context, ProgramLocationActionContext):
            return None

        context = ProgramLocationActionContext(context)
        return context.get_location()


class DecompilerEditCommentsAction(DecompilerSetCommentsAction):
    EDIT_MENUPATH = ['Comments', 'Set...']

    def __init__(self, dialog: 'CommentsDialog', name: str):
        super().__init__(dialog, name, 'Edit Comments', CodeUnit.NO_COMMENT)
        self.set_popup_menu_data(self.EDIT_MENUPATH, 'comments')
        self.set_key_binding_data(KeyEvent.VK_SEMICOLON, 0)

    def get_edit_comment_type(self) -> int:
        if isinstance(context, DecompilerActionContext):
            decomp_context = DecompilerActionContext(context)
            addr = decomp_context.get_address()
            return CodeUnit.PLATE_COMMENT if addr == decomp_context.get_function_entry_point() else CodeUnit.PRE_COMMENT
        cu = self.get_code_unit(context)
        return CommentType.get_comment_type(cu, self.get_location_for_context(context), CodeUnit.NO_COMMENT)


class CommentsDialog:
    pass


class ProgramLocationActionContext:
    def get_code_unit(self) -> 'CodeUnit':
        raise NotImplementedError('Method not implemented')


class DecompilerActionContext:
    def get_address(self) -> object:
        raise NotImplementedError('Method not implemented')

    def get_function_entry_point(self) -> object:
        raise NotImplementedError('Method not implemented')
```

Please note that the translation is not a direct copy-paste from Java to Python. It's more like an equivalent implementation in Python, considering some differences between both languages.