from abc import ABCMeta, abstractmethod

class ProgramLocationTableColumnExtensionPoint(metaclass=ABCMeta):
    """
    A convenience class that allows subclasses to signal that they implement 
    `ProgramLocationTableColumn` and that they are extension points.
    
    If you do not wish to be an extension point, but do wish to provide ProgramLocation objects,
    then you can just implement `ProgramLocationTableColumn` or extend 
    `AbstractProgramLocationTableColumn`.
    
    :param ROW_TYPE: The row object class supported by this column
    :param COLUMN_TYPE: The column object class supported by this column
    """
    @abstractmethod
    def __init__(self, row_type, column_type):
        self.row_type = row_type
        self.column_type = column_type

# Note that Python does not have direct equivalent of Java's interface or abstract classes.
# Instead we use Abstract Base Classes (ABCs) to define the structure and behavior for subclasses.

class ProgramLocationTableColumn(metaclass=ABCMeta):
    """
    A convenience class that allows subclasses to signal that they implement 
    `ProgramLocationTableColumn` and that they are extension points.
    
    If you do not wish to be an extension point, but do wish to provide ProgramLocation objects,
    then you can just implement this or extend 
    `AbstractProgramLocationTableColumn`.
    
    :param ROW_TYPE: The row object class supported by this column
    :param COLUMN_TYPE: The column object class supported by this column
    """
    @abstractmethod
    def __init__(self, row_type, column_type):
        self.row_type = row_type
        self.column_type = column_type

class AbstractProgramLocationTableColumn(metaclass=ABCMeta):
    """
    A convenience class that allows subclasses to signal that they implement 
    `ProgramLocationTableColumn` and that they are extension points.
    
    If you do not wish to be an extension point, but do wish to provide ProgramLocation objects,
    then you can just implement this or extend 
    `AbstractProgramLocationTableColumn`.
    
    :param ROW_TYPE: The row object class supported by this column
    :param COLUMN_TYPE: The column object class supported by this column
    """
    @abstractmethod
    def __init__(self, row_type, column_type):
        self.row_type = row_type
        self.column_type = column_type

