class AssemblyTreeResolver:
    def __init__(self, lang, inst_start, tree, context, ctx_graph):
        self.lang = lang
        self.inst_start = inst_start
        self.vals = {INST_START: lang.get_default_space().get_addressable_word_offset(inst_start)}
        self.tree = tree
        self.grammar = tree.get_grammar()
        self.context = context.fill_mask()
        self.ctx_graph = ctx_graph

    def resolve(self):
        results = self.resolve_branch(self.tree)
        for result in results:
            if isinstance(result, AssemblyResolution) and not result.is_error():
                vals[self.INST_NEXT] = self.lang.get_default_space().get_addressable_word_offset(
                    self.inst_start + (result).get_instruction_length())
                if result.has_backfills():
                    dbg.println("Backfilling: " + str(result))
                    result = result.backfill(self.solver, self.vals)
                    dbg.println("Backfilled final: " + str(result))
        return results

    def resolve_branch_recursive(self, branch, rec):
        try:
            dc = dbg.start("Resolving (recursive) branch: " + str(branch.get_production()))
            results = AssemblyResolutionResults()
            for ar in self.resolve_branch_non_recursive(branch):
                if not ar.is_error():
                    res = self.apply_recursion_path(ar)
                    results.absorb(res)
                else:
                    results.add(ar)
        except Exception as e:
            dbg.println("Exception: " + str(e))
        return results

    def apply_recursion_path(self, path):
        result = AssemblyResolutionResults()
        for sem in path:
            try:
                dc2 = dbg.start("Trying: " + str(sem))
                cons = sem.get_constructor()
                subres = res.copy_append_description("Applying constructor: " + str(cons))
                opvals = {}
                ...
