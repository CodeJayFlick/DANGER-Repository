import xml.etree.ElementTree as ET
from typing import List, Dict

class SleighProgramCompiler:
    EXPRESSION_SOURCE_NAME = "expression"

    def create_parser(self, language):
        translator_tag = language.build_translator_tag(language.get_address_factory(), 
                                                         language.get_unique_base(),
                                                         language.get_symbol_table())
        try:
            return PcodeParser(translator_tag)
        except Exception as e:
            raise AssertionError(e)

    def compile_template(self, language: 'SleighLanguage', parser: 'PcodeParser', source_name: str, text: str):
        template_xml = ET.tostring(parser.compile_pcode(text, self.EXPRESSION_SOURCE_NAME, 1), encoding='unicode')
        eh = MyErrorHandler()
        xml_parser = ET.fromstring(template_xml)
        construct_tpl = ConstructTpl()
        construct_tpl.restore_xml(xml_parser, language.get_address_factory())
        return construct_tpl

    def build_ops(self, language: 'SleighLanguage', template: 'ConstructTpl'):
        zero = language.get_default_space().get_address(0)
        c = SleighParserContext(zero, zero, zero, zero)
        walk = ParserWalker(c)
        emit = PcodeEmitObjects(walk)

        emit.build(template, 0)
        emit.resolve_relatives()
        return [emit.get_pcode_op()]

    def add_parser_symbols(self, parser: 'PcodeParser', symbols: Dict[int, 'UserOpSymbol']):
        for sym in symbols.values():
            parser.add_symbol(sym)

    def compile_program(self, language: 'SleighLanguage', source_name: str, lines: List[str], library: 'SleighUseropLibrary'):
        parser = self.create_parser(language)
        symbols = library.get_symbols(language)
        self.add_parser_symbols(parser, symbols)

        template = self.compile_template(language, parser, source_name, '\n'.join(lines))
        try:
            return PcodeProgram(language, self.build_ops(language, template), symbols)
        except (UnknownInstructionException, MemoryAccessException) as e:
            raise AssertionError(e)

    def compile_expression(self, language: 'SleighLanguage', expression: str):
        parser = self.create_parser(language)
        symbols = SleighExpression.CAPTURING.get_symbols(language)
        self.add_parser_symbols(parser, symbols)

        template = self.compile_template(language, parser, self.EXPRESSION_SOURCE_NAME,
                                          f"({expression})")
        try:
            return SleighExpression(language, self.build_ops(language, template), symbols)
        except (UnknownInstructionException, MemoryAccessException) as e:
            raise AssertionError(e)


class MyErrorHandler(ET.ErrorHandler):
    def warning(self, e):
        print(f"Warning: {e}")

    def error(self, e):
        print(f"Error: {e}")
