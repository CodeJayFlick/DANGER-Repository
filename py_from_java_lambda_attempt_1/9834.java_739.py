Here is the translation of the Java code to Python:
```
class RowObjectTableModel(metaclass=ABCMeta):
    """An interface to mark that the given model uses a single object to represent each row in the table."""

    @abstractmethod
    def get_name(self) -> str:
        """Returns the name of this model"""

    @abstractmethod
    def get_row_object(self, view_row: int) -> Any:
        """Returns the row object for the given row. This is the row in the UI. For models that know how to filter,
           the model row value will not match the view row value. For non-filtering models the view and model rows
           will always be the same.
        """

    @abstractmethod
    def get_row_index(self, t: Any) -> int:
        """Returns the row number for the given object.
        <p>
        Note: The index returned is always the 'view' index. For non-filtering table models,
              the 'view' and the 'model' index are the same. However, for filtering table models,
              the 'view' may be a subset of the 'model' index. Thus, it is possible if this model
              is a filtering model that the given t may not have a row value for the current state
              of the model (i.e., when the model is filtered in the view.
        """

    @abstractmethod
    def get_model_data(self) -> List[Any]:
        """Implementors should return the current data of the model. For models that support filtering,
           this will be the filtered version of the data. Furthermore, the data should be the underlying
           data and not a copy, as this method will potentially sort the given data.
        """

    @abstractmethod
    def get_column_value_for_row(self, t: Any, column_index: int) -> Any:
        """Implementors are expected to return a value at the given column index for the specified row object.
           This is essentially a more specific version of the getValueAt(int, int) that allows this class'
           comparator objects to work.
        """

    @abstractmethod
    def fire_table_data_changed(self):
        """Sends an event to all listeners that all the data inside of this model may have changed."""
```
Note:

* I used `Any` as a placeholder for the type parameter `<T>` in Java, since Python does not support generics.
* The abstract methods are marked with `@abstractmethod`, which is specific to Python's ABC (Abstract Base Classes) module.