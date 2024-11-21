class QueryOpinionServiceHandler:
    class FullQuery:
        def __init__(self, loader: str, primary: str, secondary: str, query):
            self.loader = loader
            self.primary = primary
            self.secondary = secondary
            self.query = query

        def __init__(self, full_query: 'FullQuery', loader: str, primary: str, secondary: str, query):
            if loader is None:
                self.loader = full_query.loader
            else:
                self.loader = loader
            if primary is None:
                self.primary = full_query.primary
            else:
                self.primary = primary
            if secondary is None:
                self.secondary = full_query.secondary
            else:
                self.secondary = secondary
            self.query = LanguageCompilerSpecQuery(query.processor, query.endian, query.size, query.variant, query.compiler_spec_id) if query else LanguageCompilerSpecQuery(None, None, None, None, None)

    def read(self, parser):
        stack = []
        stack.append(FullQuery(None, None, None, LanguageCompilerSpecQuery(None, None, None, None, None)))

        root = parser.start("opinions")

        while True:
            try:
                element = parser.next()
                if not element.is_start():
                    break
                top = stack[-1]

                loader = element.get_attribute("loader")
                primary = element.get_attribute("primary")
                secondary = element.get_attribute("secondary")

                processor_string = element.get_attribute("processor")
                endian_string = element.get_attribute("endian")
                size_string = element.get_attribute("size")
                variant = element.get_attribute("variant")
                compiler_spec_id_string = element.get_attribute("compilerSpecID")

                if processor_string:
                    processor = Processor.find_or_possibly_create_processor(processor_string)
                else:
                    processor = None

                if endian_string:
                    try:
                        endian = Endian.to_endian(endian_string)
                    except LoaderOpinionException as e:
                        raise LoaderOpinionException(f"no such endian: {endian_string}") from e
                else:
                    endian = None

                if size_string:
                    try:
                        size = int(size_string)
                    except ValueError as e:
                        raise LoaderOpinionException(f"invalid size integer: {size_string}") from e
                else:
                    size = None

                if compiler_spec_id_string:
                    compiler_spec_id = CompilerSpecID(compiler_spec_id_string)
                else:
                    compiler_spec_id = None

                new_full_query = FullQuery(top, loader, primary, secondary, LanguageCompilerSpecQuery(processor, endian, size, variant, compiler_spec_id))
                stack.append(new_full_query)

                QueryOpinionService.add_query(new_full_query.loader, new_full_query.primary, new_full_query.secondary, new_full_query.query)
            except StopIteration:
                break
        parser.end(root)


class LanguageCompilerSpecQuery:
    def __init__(self, processor: Processor, endian: Endian, size: int, variant: str, compiler_spec_id: CompilerSpecID):
        self.processor = processor
        self.endian = endian
        self.size = size
        self.variant = variant
        self.compiler_spec_id = compiler_spec_id


class QueryOpinionService:
    @staticmethod
    def add_query(loader: str, primary: str, secondary: str, query: LanguageCompilerSpecQuery):
        pass  # Implement this method as per your requirement

