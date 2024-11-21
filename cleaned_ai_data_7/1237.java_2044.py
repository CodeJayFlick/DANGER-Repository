import os
from ghidra_bridge import GhidraBridge
from ghidra_dbg_model_set_context_mwe_test import DbgModelSetContextMWETest

class Test(DbgModelSetContextMWETest):
    def setUp(self):
        super().setUp()
        DbgEngTest.assumeDbgengDLLLoadable()

    @staticmethod
    def make_prefix(pid, tid):
        return f"Debugger.Sessions[0x0].Processes[0x{x:08x}].Threads[0x{x:08x}]".format(
            pid, tid)

    def test_mwe(self):
        access = DbgModel.debug_create()
        client = access.get_client()
        control = client.get_control()
        registers = client.get_registers()
        so = client.get_system_objects()
        util = HDMAUtil(access)
        
        class NoisyDebugEventCallbacksAdapter:
            hit = False

            def dump_all_threads(self, runnable, reverse=False, shuffle=False):
                try:
                    restore_id = so.current_thread_id
                    threads = list(so.threads())
                    if shuffle:
                        import random; random.shuffle(threads)
                    elif reverse:
                        threads.reverse()
                    for id in threads:
                        so.set_current_thread(id); runnable.run(); 
                finally: 
                    so.set_current_thread(restore_id)

            def dump_regs_via_dx(self):
                id = so.current_thread_id
                if id.id == -1: return
                pid = so.current_process_system_id()
                tid = so.current_thread_system_id()
                prefix = self.make_prefix(pid, tid)
                
                try:
                    control.execute(f"dx {prefix}.Registers.User")
                except Exception as e:
                    print(f"Issue getting current thread: {e}")

            def dump_frame0_via_dx(self):
                id = so.current_thread_id
                if id.id == -1: return
                
                pid = so.current_process_system_id()
                tid = so.current_thread_system_id()
                prefix = self.make_prefix(pid, tid)
                
                try:
                    control.execute(f"dx {prefix}.Stack.Frames[0x0].Attributes.InstructionOffset")
                except Exception as e:
                    print(f"Issue getting current thread: {e}")

            def dump_frame0_via_k(self):
                id = so.current_thread_id
                if id.id == -1: return
                
                try:
                    stack_info = control.get_stack_trace(0, 0, 0)
                    frame = stack_info.frame[0]
                    print(f"t{id.id}.Frame[0].io={frame.InstructionOffset}")
                except Exception as e:
                    print(f"Issue getting current thread: {e}")

            def dump_pc_via_regs_api(self):
                id = so.current_thread_id
                if id.id == -1: return
                
                try:
                    print(f"t{id.id}.rip={registers.get_value_by_name('rip')}")
                    print(f"t{id.id}.eip={registers.get_value_by_name('eip')}")
                except Exception as e:
                    print(f"Issue getting current thread: {e}")

            def dump_current_thread(self):
                self.dump_regs_via_dx()
                self.dump_frame0_via_dx()
                self.dump_frame0_via_k()
                self.dump_pc_via_regs_api()

            @property
            def hit(self): return self.hit

            def breakpoint(self, bp):
                super().breakpoint(bp)
                self.hit = True; print("HIT!!!!"); 
                #self.dump_all_threads(); 
                return DebugStatus.BREAK;

            def exception(self, exception, first_chance=False):
                status = super().exception(exception, first_chance); 
                #self.dump_all_threads(); 
                return status

            def change_engine_state(self, flags, argument):
                status = super().change_engine_state(flags, argument)
                if flags.contains(ChangeEngineState.CURRENT_THREAD): return status
                if not flags.contains(ChangeEngineState.EXECUTION_STATUS): return status
                if DebugStatus.is_inside_wait(argument): return status
                if DebugStatus.from_argument(argument) != DebugStatus.BREAK: 
                    #self.dump_all_threads(self.dump_regs_via_dx, False, False); 
                    pass; 
                return status

            def change_debuggee_state(self, flags, argument):
                status = super().change_debuggee_state(flags, argument)
                return status;

        cb = NoisyDebugEventCallbacksAdapter()

        try:
            maker = ProcMaker(client, "C:\\Software\\Winmine__XP.exe")
            maker.start()
            
            client.set_event_callbacks(cb)

            symbols = client.get_symbols(); 
            #assertEqual(1, symbols.number_loaded_modules); 

            mod_winmine = symbols.module_by_name("winmine", 0)
            assert(mod_winmine is not None); base_winmine = mod_winmine.base; 
            assertEquals(0x01000000, base_winmine);

            bpt0 = control.add_breakpoint(DebugBreakpoint.BreakType.CODE)

            bpt0.set_offset(base_winmine + 0x367a)
            bpt0.set_flags(DebugBreakpoint.BreakFlags.ENABLED); 

            control.set_execution_status(DebugStatus.GO); 
            while not cb.hit: print("Not hit yet. Waiting"); control.wait_for_event(); print("   ..."); 
            print("DONE");

            for ent in cb.frame0s_by_t.items():
                print(f"IO-cached(0x{x:08x}): {ent[1].get_elements()[0].key_value('Attributes').key_value('InstructionOffset')}")
            cb.dump_frame0_via_dx();

            reader = BufferedReader(InputStreamReader(sys.stdin)); 
            while True:
                sys.stderr.write(control.prompt_text); 
                #control.prompt(BitmaskSet.of(), "Hello?>"); 
                cmd = reader.readline(); control.execute(cmd)
                if control.execution_status.should_wait: control.wait_for_event()
        finally:
            pass
