import unittest
from parameterized import parameterized
from micrometer.core.instrument import AbstractTimer, Clock, Counter, DistributionSummary, FunctionCounter, FunctionTimer, Gauge, Measurement, Meter, Timer
from micrometer.core.instrument.util import Id, Tags

class TestMetricsVersionStore(unittest.TestCase):

    @parameterized.expand([
        ("tohash", None, lambda vs: vs.to_hash("mock-branch"), [Exception]),
        ("toref", None, lambda vs: vs.to_ref("mock-branch"), [ReferenceNotFoundException, ReferenceConflictException, ReferenceAlreadyExistsException]),
        ("commit", None, lambda vs: vs.commit("mock-branch", Optional.empty(), "metadata", []), [ReferenceNotFoundException, ReferenceConflictException]),
        ("transplant", None, lambda vs: vs.transplant("mock-branch", Optional.empty(), []), [ReferenceNotFoundException, ReferenceConflictException]),
        ("merge", None, lambda vs: vs.merge(Hash.of("42424242"), BranchName.of("mock-branch"), Optional.empty()), [ReferenceNotFoundException, ReferenceConflictException]),
        ("assign", None, lambda vs: vs.assign(BranchName.of("mock-branch"), Optional.empty(), Hash.of("12341234")), [ReferenceNotFoundException, ReferenceConflictException]),
        ("create", None, lambda vs: vs.create(BranchName.of("mock-branch"), Optional.of(Hash.of("cafebabe"))), [ReferenceAlreadyExistsException]),
        ("delete", None, lambda vs: vs.delete(BranchName.of("mock-branch"), Optional.of(Hash.of("cafebabe"))), [ReferenceNotFoundException, ReferenceConflictException]),
        ("getcommits", None, lambda vs: vs.get_commits(BranchName.of("mock-branch")), [ReferenceNotFoundException]),
        ("getkeys", None, lambda vs: vs.get_keys(Hash.of("cafe4242")), [ReferenceNotFoundException]),
        ("getnamedrefs", None, VersionStore.get_named_refs, [RuntimeError])
    ])
    def test_version_store_invocation(self, op_name, expected_throw, result_supplier, failures):
        registry = TestMeterRegistry()
        if expected_throw is not None:
            stubber = do_throw(expected_throw)
        elif result_supplier is not None:
            stubber = do_return(result_supplier.get())
        else:
            stubber = do_nothing()

        mocked_version_store = mock(VersionStore)
        stubber.when(mocked_version_store).thenReturn(None)

        version_store = MetricsVersionStore(mocked_version_store, registry, registry.clock)

        timer_id = Id("nessie.versionstore.request", Tags.of(error=str(bool(expected_throw)), request=op_name, application="Nessie"), "nanoseconds", None, Type.TIMER)
        timer = registry.timers.get(timer_id)

        if expected_throw is not None:
            with self.assertRaises(type(expected_throw)):
                version_store_exec(VersionStoreFunction(version_store), stubber)
        else:
            result = version_store_exec(VersionStoreFunction(version_store), stubber)
            assert result is not None

    def test_timer(self):
        timer = TestTimer(Id("nessie.versionstore.request", Tags.of(error=str(bool(expected_throw)), request=op_name, application="Nessie"), "nanoseconds", None, Type.TIMER))
        recorded = [1L]
        timer.record_non_negative(1L, TimeUnit.NANOSECONDS)
        self.assertEqual(timer.count(), 1)
        self.assertAlmostEqual(timer.total_time(TimeUnit.NANOSECONDS), expected_duration)

class VersionStoreInvocation:
    def __init__(self, op_name, function, result_supplier, failures):
        self.op_name = op_name
        self.function = function
        self.result_supplier = result_supplier
        self.failures = failures

class ThrowingFunction:
    def __call__(self, arg):
        raise Exception("Not implemented")

def version_store_exec(version_store_function, stubber):
    try:
        return version_store_function()
    except Exception as e:
        print(f"Caught exception: {e}")
        return None
