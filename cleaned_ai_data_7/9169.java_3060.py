from abc import ABC, abstractmethod
import io

class BlockStreamHandle(ABC):
    @abstractmethod
    def open_block_stream(self) -> object:
        """Invoked by client to establish the remote connection and return 
           the opened block stream.
        
        Returns:
            connected/open block stream
        
        Raises:
            Exception (not explicitly IOException, but similar concept)
        """
