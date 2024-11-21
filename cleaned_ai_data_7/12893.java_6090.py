class SolverTest:
    nil = MaskedLong(0)
    unk = MaskedLong(-1)
    one = MaskedLong(1)

    def test_and(self):
        self.assertEqual(nil, nil & nil)
        self.assertEqual(nil, nil & unk)
        self.assertEqual(nil, nil & one)

        self.assertEqual(nil, unk & nil)
        self.assertEqual(unk, unk & unk)
        self.assertEqual(unk, unk & one)

        self.assertEqual(nil, one & nil)
        self.assertEqual(unk, one & unk)
        self.assertEqual(one, one & one)

    def test_inv_and(self):
        try:
            res = one.inv_and(nil)
            self.fail()
        except Exception as e:
            pass

        self.assertEqual(unk, nil.inv_and(nil))
        self.assertEqual(unk, nil.inv_and(unk))
        self.assertEqual(nil, nil.inv_and(one))

        self.assertEqual(unk, unk.inv_and(nil))
        self.assertEqual(unk, unk.inv_and(unk))
        self.assertEqual(unk, unk.inv_and(one))

    def test_or(self):
        self.assertEqual(nil, nil | nil)
        self.assertEqual(unk, nil | unk)
        self.assertEqual(one, nil | one)

        self.assertEqual(unk, unk | nil)
        self.assertEqual(unk, unk | unk)
        self.assertEqual(one, unk | one)

        self.assertEqual(one, one | nil)
        self.assertEqual(one, one | unk)
        self.assertEqual(one, one | one)

    def test_inv_or(self):
        try:
            res = nil.inv_or(nil)
            self.fail()
        except Exception as e:
            pass

        self.assertEqual(nil, nil.inv_or(nil))
        self.assertEqual(nil, nil.inv_or(unk))
        self.assertEqual(nil, nil.inv_or(one))

        self.assertEqual(unk, unk.inv_or(nil))
        self.assertEqual(unk, unk.inv_or(unk))
        self.assertEqual(unk, unk.inv_or(one))

    def test_xor(self):
        self.assertEqual(nil, nil ^ nil)
        self.assertEqual(unk, nil ^ unk)
        self.assertEqual(one, nil ^ one)

        self.assertEqual(unk, unk ^ nil)
        self.assertEqual(unk, unk ^ unk)
        self.assertEqual(nil, unk ^ one)

        self.assertEqual(one, one ^ nil)
        self.assertEqual(unk, one ^ unk)
        self.assertEqual(nil, one ^ one)

    def test_write_unks(self):
        str = "XX:[x10x]5:AA"
        a = AssemblyPatternBlock.fromString(str)
        self.assertEqual(str, a.toString())
        toWrite = MaskedLong.fromMaskAndValue(0x3, 0x2)
        chg = ContextOp()
        b = a.writeContextOp(chg, toWrite)
        self.assertEqual("XX:[x10x]5:AA[1xx1]:[0xxx]X", b.toString())

    def test_cat_or_solver(self):
        parser = XmlPullParserFactory.create("<or_exp>\n" +
                                               "   <lshift_exp>\n" +
                                               "     <tokenfield bigendian='false' signbit='false' bitstart='0' bitend='3' bytestart='0' byteend='0' shift='0'/>\n" +
                                               "     <intb val='4'/>\n" +
                                               "   </lshift_exp>\n" +
                                               "</or_exp>\n", "Test", None, True)
        exp = PatternExpression.restoreExpression(parser, None)
        solver = RecursiveDescentSolver.getSolver()
        res = solver.solve(exp, MaskedLong.fromLong(0x78), {}, {}, AssemblyResolution("NOP", None), "Test")
        e = AssemblyResolvedConstructor.fromString("ins:SS:SS:SS:[01xx][x0xx]:XX:XX", "Test", None)
        self.assertEqual(e, res)

    def test_get_operand_export_size32(self):
        ct = find_constructor("AARCH64:BE:64:v8A", "Imm_uimm_exact32", "always")
        ctpl = ct.getTempl()
        htpl = ctpl.getResult()
        self.assertEqual(32, htpl.getSize())

    def test_get_operand_export_size64(self):
        ct = find_constructor("AARCH64:BE:64:v8A", "addrRegShift64",
                              "ins:SS:SS:SS:[01xx][x0xx]:XX:XX:XX")
        ctpl = ct.getTempl()
        htpl = ctpl.getResult()
        self.assertEqual(64, htpl.getSize())

    def test_get_operand_export_size16(self):
        ct = find_constructor("avr8:LE:16:extended", "next16memPtrVal1", "always")
        ctpl = ct.getTempl()
        htpl = ctpl.getResult()
        self.assertEqual(16, htpl.getSize())

    @staticmethod
    def test_experiment_get_operand_export_size1():
        if not Application.is_initialized():
            Application.initialize_application(new GhidraApplicationLayout(), new ApplicationConfiguration())
        provider = SleighLanguageProvider()
        lang = provider.get_language(new LanguageID("AARCH64:BE:64:v8A"))
        consref = AtomicReference[Constructor]()
        traverse_constructors(lang, new ConstructorEntryVisitor() {
            @Override
            public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons) {
                if "Imm_logical_imm32_operand".equals(subtable.getName()):
                    if "ins:SS:C[00xx]:[x0xx]X:XX:XX".equals(pattern.toString()):
                        consref.set(cons)
                        return FINISHED
                    } else:
                        return CONTINUE

        })
        ct = consref.get()
        st = new ConstructState(null) {
            @Override
            public Constructor getConstructor() {
                return ct
            }
        }

    def test_in_range(self):
        self.assertTrue(MaskedLong(0).is_in_range(0xf, True))
        self.assertFalse(MaskedLong(1).is_in_range(0xf, False))

        self.assertTrue(MaskedLong(-8).is_in_range(0xff, True))
        self.assertFalse(MaskedLong(-9).is_in_range(0xff, True))

        # ... and so on
