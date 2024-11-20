class ProgramLocationTableRowMapper(metaclass=ABCMeta):
    """An interface that allows implementors to map an object of one type to another.
    
    This is useful for table models that have row types that are easily converted 
    to other more generic types. For example, the Bookmarks table model's data 
    is based upon Bookmark objects. Furthermore, those objects are easily 
    converted to ProgramLocations and Addresses. By creating a mapper for these 
    types, the table model can now show dynamic columns that work on ProgramLocations
    and Addresses.
    
    This interface is an ExtensionPoint so that once created, they will be ingested automatically
    by Ghidra. Once discovered, these mappers will be used to provide dynamic columns to 
    tables with row types that match ROW_TYPE.
    
    @param <ROW_TYPE> The row type of a given table model
    @param <EXPECTED_ROW_TYPE> The row type expected by dynamic columns (e.g., ProgramLocations, 
                                Addresses, etc).
    @see AbstractDynamicTableColumn
    @see TableUtils
    """
    def __init__(self):
        pass

    @abstractmethod
    def create_mapped_table_column(self, destination_column: 'ProgramLocationTableColumn') -> 'MappedProgramLocationTableColumn':
        """Creates a table column that will create a table column that knows how to map the 
           given ROW_TYPE to the type of the column passed in, the EXPECTED_ROW_TYPE.
        
        @param COLUMN_TYPE The column type of the given and created columns
        @param destination_column The existing column, which is based upon EXPECTED_ROW_TYPE,
                                   that we want to be able to use with the type we have, the ROW_TYPE.
        """
        pass

class MappedProgramLocationTableColumn:
    def __init__(self, program_location_table_row_mapper: 'ProgramLocationTableRowMapper', 
                 destination_column: 'ProgramLocationTableColumn'):
        self.program_location_table_row_mapper = program_location_table_row_mapper
        self.destination_column = destination_column
