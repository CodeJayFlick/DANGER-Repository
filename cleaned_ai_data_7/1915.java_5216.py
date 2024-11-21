import unittest
from ghidra.app import services as srvs
from ghidra.util.exception import InvalidInputException
from ghidra.dbg.model.target import TargetObject
from ghidra.dbg.model.interpreter import Interpreter
from ghidra.dbg.model.lldb import LldbModelTargetSession

class AbstractModelForLldbSessionActivationTest(unittest.TestCase):

    def __init__(self, methodName='runTest'):
        super(AbstractModelForLldbSessionActivationTest, self).__init__(methodName)

    @property
    def m(self):
        return srvs.getModel()

    def getSessionPattern(self):
        pass  # abstract method

    def getCount(self):
        return 3

    def getSpecimen(self):
        return "MacOSSpecimen.PRINT"

    def getExpectedSessionPath(self):
        pass  # abstract method

    def getIndexFromCapture(self, line):
        pass  # abstract method

    @unittest.skip("Not implemented")
    def testDefaultFocusIsAsExpected(self):

        expected_default_focus = self.getExpectedDefaultActivePath()
        if not expected_default_focus:
            raise unittest.SkipTest('No default focus path')

        self.m.build()

        activatable_things = self.getActivatableThings()
        found = {k: v for k, v in zip(*self.m.findAll(Interpreter, self.getExpectedSessionPath(), True))}
        # The default must be one of the activatable objects
        keys = list(found.keys())
        obj = found[keys[-1]]
        self.assertTrue(obj in activatable_things)
        if hasattr(self.m, 'hasInterpreter'):
            interpreter = self.findInterpreter(obj)
            self.assertActiveViaInterpreter(obj, interpreter)

    @unittest.skip("Not implemented")
    def testActivateEachOnce(self):

        self.m.build()

        active_scope = srvs.getActiveScope()
        activatable_things = self.getActivatableThings()
        for obj in activatable_things:
            active_scope.requestActivation(obj)
            if hasattr(self.m, 'hasInterpreter'):
                interpreter = self.findInterpreter(obj)
                self.assertActiveViaInterpreter(obj, interpreter)

    @unittest.skip("Not implemented")
    def testActivateEachTwice(self):

        self.m.build()

        active_scope = srvs.getActiveScope()
        activatable_things = self.getActivatableThings()
        for obj in activatable_things:
            active_scope.requestActivation(obj)
            if hasattr(self.m, 'hasInterpreter'):
                interpreter = self.findInterpreter(obj)
                self.assertActiveViaInterpreter(obj, interpreter)
            active_scope.requestActivation(obj)
            if hasattr(self.m, 'hasInterpreter'):
                interpreter = self.findInterpreter(obj)
                self.assertActiveViaInterpreter(obj, interpreter)

    @unittest.skip("Not implemented")
    def testActivateEachViaInterpreter(self):

        assume(hasattr(self.m, 'hasInterpreter'))
        self.m.build()

        activatable_things = self.getActivatableThings()
        for obj in activatable_things:
            interpreter = self.findInterpreter(obj)
            self.activateViaInterpreter(obj, interpreter)
            self.assertActiveViaInterpreter(obj, interpreter)

    def getExpectedDefaultActivePath(self):
        pass  # abstract method

    @unittest.skip("Not implemented")
    def assertActiveViaInterpreter(self, expected, interpreter):

        output = srvs.getDebugger().executeCapture('target list')
        line = next((l for l in output.split('\n') if l.strip().startswith('*')), None).strip()
        proc_id = self.getIdFromCapture(line)
        exp_id = self.getSessionPattern().matchIndices(expected.getPath())[0]
        self.assertEqual(long(exp_id, 16), long(proc_id))

    def findInterpreter(self, obj):
        return Interpreter(obj)

if __name__ == '__main__':
    unittest.main()
