class LabelSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter
        self.symbol = None
        super().__init__()

    def apply(self):
        if not self.applicator.get_pdb_applicator_options().apply_instruction_labels():
            return

        name = self.symbol.name
        symbol_address = self.applicator.get_address(self.symbol)
        if self.applicator.is_invalid_address(symbol_address, name):
            return

        function_manager = self.applicator.get_program().get_function_manager()

        if name.startswith("$") and not name.contains(Namespace.DELIMITER):
            f = function_manager.get_function_containing(symbol_address)
            if f is not None and not f.name.equals(name):
                name = NamespaceUtils.get_namespace_qualified_name(f, name, True)

        self.applicator.create_symbol(symbol_address, name, False)


class MsSymbolApplier:
    def __init__(self):
        pass

    def apply(self):
        raise NotImplementedError


def main():
    applicator = None
    iter = None
    applier = LabelSymbolApplier(applicator, iter)
    try:
        applier.apply()
    except PdbException as e:
        print(f"Pdb exception: {e}")
    except CancelledException as e:
        print(f"Cancelled exception: {e}")


if __name__ == "__main__":
    main()

