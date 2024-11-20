import asyncio
from typing import Any, Callable, Dict, List

class DebuggerGoToTrait:
    def __init__(self):
        self.current = None  # type: DebuggerCoordinates
        self.go_to_dialog = None  # type: GoToDialog

    async def go_to_address(self, address: str) -> bool:
        pass  # abstract method to be implemented by subclasses

    def set_current_coordinates(self, coordinates: 'DebuggerCoordinates') -> None:
        self.current = coordinates

    def install_action(self) -> Any:
        action = GoToAction(
            plugin=self.plugin,
            enabled_when=lambda ctx: self.current.view is not None,
            on_action=self.activated_go_to
        )
        return action

    async def activated_go_to(self, context: 'ActionContext') -> None:
        view = self.current.view  # type: TraceProgramView
        if view is None:
            return
        language = view.language  # type: Language
        if not isinstance(language, SleighLanguage):
            return
        await self.go_to_dialog.show((SleighLanguage) language)

    async def go_sleigh(self, space_name: str, expression: str) -> bool:
        language = self.current.view.language  # type: Language
        if not isinstance(language, SleighLanguage):
            raise ValueError("Current trace does not use Sleigh")
        slang = (SleighLanguage) language
        address_space = language.get_address_factory().get_address_space(space_name)
        if address_space is None:
            raise ValueError(f"No such address space: {space_name}")
        expr = await self.compile_expression(slang, expression)
        return await self.go_sleigh(address_space, expr)

    async def go_sleigh(self, address_space: 'AddressSpace', expression: 'SleighExpression') -> bool:
        executor = TracePcodeUtils.executor_for_coordinates(self.current)
        result = await asyncio.create_task(expression.evaluate(executor))
        offset = result.result
        return await self.go_to_address(address_space.get_address(Utils.bytes_to_long(offset, len(offset), expression.language.is_big_endian())))

    async def compile_expression(self, slang: 'SleighLanguage', expression: str) -> 'SleighExpression':
        pass  # abstract method to be implemented by subclasses

class GoToDialog:
    def __init__(self):
        self.debugger_go_to_trait = None  # type: DebuggerGoToTrait
