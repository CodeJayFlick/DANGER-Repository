class AssemblyTestCase:
    def __init__(self):
        self.verbose_dis = False
        self.default_addr = 0x40000000L
        self.lang = None
        self.context = None
        self.dbg_timer = DbgTimer()

    @property
    def verbose_dis(self):
        return self._verbose_dis

    @verbose_dis.setter
    def verbose_dis(self, value):
        self._verbose_dis = value

    def get_language_id(self):
        pass  # abstract method to be implemented by subclasses

    def setup(self):
        lang_id = self.get_language_id()
        if not self.setup_lang_id == str(lang_id):
            provider = SleighLanguageProvider()
            self.lang = provider.get_language(lang_id)
            self.context = AssemblyDefaultContext(self.lang)
            self.setup_lang_id = str(lang_id)

    @property
    def setup_lang_id(self):
        return self._setup_lang_id

    @setup_lang_id.setter
    def setup_lang_id(self, value):
        self._setup_lang_id = value

    def tearDown(self):
        pass  # no-op for now

    @staticmethod
    def dbg_print_trees(trees):
        if trees:
            print("Got {} tree(s).".format(len(trees)))
            suggestions = set()
            for result in trees:
                if not result.is_error():
                    acc = AssemblyParseAcceptResult(result)
                    tree = acc.get_tree()
                    tree.print(self.dbg_timer)
                else:
                    err = AssemblyParseErrorResult(result)
                    print(err)
                    if err.get_buffer() == "":
                        suggestions.update(err.get_suggestions())
            print("Proposals: {}".format(suggestions))

    @staticmethod
    def disassemble(addr, ins, ctx):
        at = self.lang.get_default_space().get_address(addr)
        context.set_context_register(ctx)
        buf = ByteMemBufferImpl(at, ins, self.lang.is_big_endian())
        logger = SleighDebugLogger(buf, context, lang, SleighDebugMode.VERBOSE)
        ip = lang.parse(buf, context, False)
        if self.verbose_dis:
            print("SleighLog:\n" + logger.to_string())
        return PseudoInstruction(at, ip, buf, context)

    @staticmethod
    def dump_constructor_tree(ins):
        sip = SleighInstructionPrototype(ins.get_prototype())
        return sip.dump_constructor_tree()

    @staticmethod
    def format_with_cons(ins):
        return "{} {}".format(ins.to_string(), self.dump_constructor_tree(ins))

    @staticmethod
    def check_one_compat(instr, rr):
        ins = AssemblyPatternBlock.from_string(instr)
        print("Checking against: {}".format(ins))
        errors = set()
        misses = set()
        for ar in rr:
            if ar.is_error():
                errors.add((AssemblyResolvedError) ar)
                continue
            rcon = (AssemblyResolvedConstructor) ar
            try:
                print("{} {}".format(rcon.line_to_string(), NumericUtilities.convert_bytes_to_string(ins)))
                pi = self.disassemble(self.default_addr, ins, ctx.get_vals())
                cons = self.dump_constructor_tree(pi)
                dis = pi.to_string().strip()
                if not rr.contains(dis):
                    raise DisassemblyMismatchException("Desired instruction bytes do not disassemble to a desired string: {} ; found instead: {}".format(rr, dis))
            except (InsufficientBytesException, UnknownInstructionException, AddressOverflowException, MemoryAccessException) as e:
                print("Cannot disassemble desired instruction bytes", e)
        if errors or misses:
            raise AssertionError("There was an unexpected semantic error")

    def run_test(self, assembly, instr, disassemblies=None, addr=self.default_addr, ctxstr=None):
        assembler = Assemblers.get_assembler(self.lang, AssemblySelector())
        try:
            if not ctxstr:
                assembler.assemble_line(self.lang.get_default_space().get_address(addr), assembly)
            else:
                sas = SleighAssembler(assembler)
                sas.assemble_line(self.lang.get_default_space().get_address(addr), assembly, AssemblyPatternBlock.from_string(ctxstr))
        except (AssemblySemanticException) as e:
            if not self.check_all_semantic_errors:
                raise AssertionError("There was an unexpected semantic error: {}".format(e))

    def assert_one_compat_rest_exact(self, assembly, instr):
        self.run_test(assembly, instr)

    def assert_one_compat_rest_exact(self, assembly, instr, disassemblies=None):
        if not disassemblies:
            disassemblies = [assembly]
        self.run_test(assembly, instr, set(disassemblies))

    def assert_all_syntax_errors(self, assembly):
        self.run_test(assembly, None)

    def assert_all_semantic_errors(self, assembly):
        self.run_test(assembly, None)
