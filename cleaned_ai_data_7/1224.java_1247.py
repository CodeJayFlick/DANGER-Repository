import threading
from collections import defaultdict, deque

class UnknownWithUtils:
    def __init__(self):
        pass

    @staticmethod
    def pause():
        try:
            input()
        except Exception as e:
            raise AssertionError(e)

    @staticmethod
    def error(message):
        print(f"Error: {message}")

    class RefAnalyzerEntry:
        def __init__(self, ptr):
            self.ptr = ptr
            self.my_count = 0

        def verify_valid(self, actual, wrapper_name):
            if self.my_count < 0 or actual < 0:
                UnknownWithUtils.error(f"COM mine or actual ref-count below 0 in {wrapper_name} wrapper={self.ptr}")

        def verify_thread(self):
            current_thread = threading.current_thread()
            if not hasattr(self, 'thread') or self.thread != current_thread:
                print("COM use by distinct threads ptr=", self.ptr)

    class DisabledRefAnalyzer:
        @staticmethod
        def observe_call(ptr, wrapper_name):
            pass

        @staticmethod
        def observed_add_ref_via_result(ptr, wrapper_name):
            pass

        @staticmethod
        def observed_query_interface(riid, ppv_object, hr, wrapper_name):
            pass

        @staticmethod
        def observed_release(count, wrapper_name):
            pass

    class EnabledRefAnalyzer:
        _refs = defaultdict(UnknownWithUtils.RefAnalyzerEntry)
        _qis = deque()

        @classmethod
        def get_entry(cls, ptr):
            return cls._refs[ptr]

        @classmethod
        def get_entry_or_create(cls, ptr):
            if not hasattr(cls, '_refs'):
                cls._refs = defaultdict(UnknownWithUtils.RefAnalyzerEntry)
            return cls.get_entry(ptr)

        @classmethod
        def remove_entry(cls, ptr):
            del cls._refs[ptr]

        @classmethod
        def expect_wrapper(cls, ptr):
            cls._qis.append(ptr)

        @classmethod
        def unexpect_wrapper(cls, ptr):
            if ptr in cls._qis:
                cls._qis.remove(ptr)

        def observe_call(self, ptr, wrapper_name):
            entry = self.get_entry_or_create(ptr)
            actual_count = entry.my_count
            entry.verify_valid(actual_count, wrapper_name)
            entry.verify_thread()

        @staticmethod
        def observed_add_ref_via_result(ptr, wrapper_name):
            print(f"COM Presumed AddRef: {ptr}, wrapper={wrapper_name}")

        @staticmethod
        def observed_query_interface(riid, ppv_object, hr, wrapper_name):
            ptr = ppv_object.get_value()
            print(f"COM QueryInterface: {wrapper_name} (riid->{riid.to_guid_string()},ppvObject->{ptr}) ={hr}")
            UnknownWithUtils.EnabledRefAnalyzer.expect_wrapper(ptr)

        @staticmethod
        def observed_release(count, wrapper_name):
            print(f"COM Release: {wrapper_name}() = {count}")

    ANALYZER = DisabledRefAnalyzer()

    class VTableIndex:
        def __init__(self):
            pass

        @classmethod
        def follow(cls, prev):
            all = list(prev.__subclasses__())
            start = all[0].getIndex() - all[0].ordinal()
            return len(all) + start

    def _invoke_hr(self, idx, *args):
        # print(f"{threading.current_thread()} invoked {idx} with args={args}")
        return self._invoke_native_object(idx.getIndex(), args)

    def QueryInterface(self, riid, ppv_object):
        ANALYZER.observe_call("QueryInterface")
        hr = super().QueryInterface(riid, ppv_object)
        ANALYZER.observed_query_interface(riid, ppv_object, hr, "QueryInterface")
        return hr

    def AddRef(self):
        count = super().AddRef()
        ANALYZER.observed_add_ref(count, self)
        return count

    def Release(self):
        count = super().Release()
        ANALYZER.observed_release(count, self)
        return count

    def get_ref_count(self):
        added = self.AddRef()
        count = self.Release()
        if added - 1 != count:
            print(f"COM ref-count impl anomaly wrapper={self} added={added}, count={count}")
        return count
