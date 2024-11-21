class AbstractSortedTableModel:
    def __init__(self):
        self.NO_SORT_COMPARATOR = lambda o1, o2: 0
        self.pending_sort_state = None
        self.sort_state = TableSortState.create_unsorted_sort_state()
        self.is_sort_pending = False

    @property
    def has_ever_sorted(self):
        return hasattr(self, 'has_ever_sorted') and getattr(self, 'has_ever_sorted')

    def set_default_table_sort_state(self, default_sort_state: 'TableSortState'):
        self.sort_state = default_sort_state
        if not self.sort_state:
            self.sort_state = TableSortState.create_unsorted_sort_state()

    def add_sort_listener(self, l):
        listeners.add(l)

    @abstractmethod
    def get_row_object(self, view_row) -> T:
        pass

    @abstractmethod
    def get_index_for_row_object(self, row_object: T) -> int:
        pass

    def fire_table_changed(self, e):
        super().fire_table_changed(e)
        self.re_sort()

    def re_sort(self):
        model_data = self.get_model_data()
        if not model_data or len(model_data) == 0:
            return
        self.pending_sort_state = self.sort_state
        self.sort(model_data, TableSortingContext(self.sort_state, self.get_comparator_chain(self.sort_state)))

    @property
    def table_sort_state(self):
        return self.sort_state

    @abstractmethod
    def get_primary_sort_column_index(self) -> int:
        pass

    def set_table_sort_state(self, new_sort_state: 'TableSortState'):
        if not self.is_valid_sort_state(new_sort_state):
            raise ValueError("Unable to sort the table by the given sort state!: " + str(new_sort_state))
        do_set_table_sort_state(new_sort_state)

    @staticmethod
    def is_sorted() -> bool:
        return True

    def get_pending_sort_state(self) -> 'TableSortState':
        return self.pending_sort_state

    def initialize_sorting(self):
        if hasattr(self, 'has_ever_sorted') and getattr(self, 'has_ever_sorted'):
            return
        self.has_ever_sorted = True
        self.is_sort_pending = True
        pending_sort_state = self.sort_state
        Swing.run_later(lambda: self.sort(get_model_data(), create_sorting_context(pending_sort_state)))

    def sort_completed(self, sorting_context):
        if not hasattr(self, 'has_ever_sorted'):
            return
        has_ever_sorted = False  # signal that we have sorted at least one time

    @abstractmethod
    def notify_model_sorted(self) -> None:
        pass

class TableSortState:
    @staticmethod
    def create_unsorted_sort_state() -> 'TableSortState':
        pass

    @property
    def is_unsorted(self):
        return False  # default implementation, should be overridden in subclasses

    @abstractmethod
    def get_sorted_column_count(self) -> int:
        pass

class TableSortingContext:
    def __init__(self, sort_state: 'TableSortState', comparator_chain):
        self.sort_state = sort_state
        self.comparator_chain = comparator_chain

# Inner Classes
class ComparatorLink:
    @abstractmethod
    def compare(self, t1, t2) -> int:
        pass

class EndOfChainComparator(ComparatorLink):
    @staticmethod
    def compare(t1: T, t2: T) -> int:
        if isinstance(t1, Comparable) and isinstance(t1, type(t2)):
            return (t1).compareTo(t2)
        else:
            return System.identityHashCode(t1) - System.identityHashCode(t2)

class ReverseComparator(ComparatorLink):
    def __init__(self, comparator: Comparator[T]):
        self.comparator = comparator

    @abstractmethod
    def compare(self, t1: T, t2: T) -> int:
        pass

# Inner Classes
class StringBasedBackupRowToColumnComparator(ComparatorLink):
    @staticmethod
    def compare(c1: Object, c2: Object) -> int:
        if c1 == c2:
            return 0
        s1 = get_column_string_value(c1)
        s2 = get_column_string_value(c2)

        if not s1 or not s2:
            return TableComparators.compare_with_null_values(s1, s2)
        else:
            return s1.compareToIgnoreCase(s2)

    @staticmethod
    def get_column_string_value(column_value: Object) -> str:
        # just use the toString(), which may or may not produce a good value (this will catch the cases where the column value is itself a string)
        if column_value == None:
            return None
        else:
            return column_value.toString()
