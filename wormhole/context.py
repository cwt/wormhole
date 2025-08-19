from typing import Dict, Any
import time


class RequestContext:
    """
    A context object that encapsulates request-specific information and shared state
    to reduce function call overhead by minimizing parameter passing.
    """

    def __init__(
        self,
        ident: Dict[str, str],
        verbose: int = 0,
    ) -> None:
        """
        Initialize the request context.

        Args:
            ident: Dictionary containing identifier and client details
            verbose: Verbosity level for logging
        """
        self.ident = ident
        self.verbose = verbose
        self.start_time = time.time()
        self.client_ip = ident.get("client", "unknown")

    def get_elapsed_time(self) -> float:
        """
        Get the elapsed time since the request started.

        Returns:
            float: Elapsed time in seconds
        """
        return time.time() - self.start_time
