import unittest
from ghidra.app.plugin.core.debug.service.model import DebuggerModelServiceTest
from ghidra.app.plugin.core.debug.event.model_object_focused_plugin_event import ModelObjectFocusedPluginEvent
from ghidra.dbg.target import TargetEnvironment

class TestDebuggerModelService(unittest.TestCase):
    def setUp(self):
        self.model_service = DebuggerModelService()

    @unittest.skip("This test is not implemented yet")
    def test_get_model_factories(self):
        # This method sets the model factories and then checks if they are equal
        pass

    @unittest.skip("This test is not implemented yet")
    def test_listen_model_factory_added(self):
        # This method adds a factory changed listener, waits for a new factory to be added,
        # and verifies that it was added.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_get_program_launch_offers(self):
        # This method creates a program with an executable path, sets the model factories
        # to include a TestDebuggerModelFactory, gets the launch offers for the program,
        # and verifies that they are equal.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_get_models(self):
        # This method creates a new model, adds it to the service's models, and then
        # checks if the models returned by getModels() include this newly added model.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_listen_model_added(self):
        # This method adds a model changed listener, waits for a new model to be added,
        # and verifies that it was added.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_get_trace_recorders(self):
        # This method creates a new process with threads, records the target using
        # recordTarget(), gets the trace recorder for this target, and then checks if
        # there are any trace recorders.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_listen_trace_recorder_added(self):
        # This method adds a trace recorder changed listener, waits for a new trace
        # recorder to be added, and verifies that it was added.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_record_then_close_stops_recording(self):
        # This method records the target using recordTarget(), closes the model,
        # and then checks if recording has stopped.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_record_and_open_then_close_model_and_trace_leaves_no_consumers(self):
        # This method creates a new process with threads, records the target using
        # recordTarget(), closes the model and trace, and then checks if there are no consumers.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_get_recorder_by_target(self):
        # This method gets the recorder for a given target and verifies that it's equal to the expected value.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_get_recorder_by_trace(self):
        # This method gets the recorder for a given trace and verifies that it's equal to the expected value.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_get_target_thread(self):
        # This method creates a new process with threads, records the target using
        # recordTarget(), waits for the thread to appear in the recorder,
        # and then checks if it's equal to the expected value.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_target_focus(self):
        # This method requests focus on a given thread, verifies that the target
        # has been focused, and then waits for another request of focus on this same thread,
        # verifying again if it's equal to the expected value.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_current_model_null_after_close(self):
        # This method activates a model, verifies that it's current, closes the
        # model, and then checks if there are no more models.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_connect_dialog_populates(self):
        # This method shows the connect dialog, selects an entry from the dropdown,
        # verifies that it's equal to the expected value, and then closes the
        # dialog.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_record_best_offer_recognized(self):
        # This method records a best offer recognized by the model service,
        # waits for the target to be recorded, verifies that there's one trace recorder,
        # and then checks if it's equal to the expected value.
        pass

    @unittest.skip("This test is not implemented yet")
    def test_record_best_offer_unrecognized(self):
        # This method records a best offer unrecognized by the model service,
        # waits for the target to be recorded, verifies that there are no trace recorders,
        # and then checks if it's equal to the expected value.
        pass

if __name__ == '__main__':
    unittest.main()
