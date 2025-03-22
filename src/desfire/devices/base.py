import abc


class Device:
    """Abstract base class which uses underlying device communication channel."""

    @abc.abstractmethod
    def transceive(self, bytes: bytes) -> bytes:
        """
        Send in APDU request and wait for the response.

        Args:
            bytes (bytes): Outgoing bytes as list of bytes or byte array

        Returns:
            bytes: List of bytes or byte array from the device.
        """
        raise NotImplementedError("Base class must implement")
