class ApplicationID:
    """
    An ApplicationID is a unique identifier for an application on a DESFire card.
    It is a 3-byte value that is used to identify the application.
    """

    def __init__(self, application_id: bytes | str | int | None = None):
        if application_id is None:
            self.application_id = bytes([0, 0, 0])
        elif isinstance(application_id, str):
            if len(application_id) != 6:
                raise ValueError("Application ID must be a 6-character hex string.")
            self.application_id = bytes.fromhex(application_id)
        elif isinstance(application_id, int):
            if application_id < 0 or application_id > 0xFFFFFF:
                raise ValueError("Application ID must be a 3-byte integer.")
            self.application_id = bytes([application_id])[1:]
        elif isinstance(application_id, bytes):
            if len(application_id) != 3:
                raise ValueError("Application ID must be a 3-byte value.")
            self.application_id = application_id

    application_id: bytes

    def get(self) -> bytes:
        """
        Get the Application ID as a 3-byte value.
        """
        return self.application_id

    def __eq__(self, other: object) -> bool:
        """
        Check if two Application IDs are equal.
        """
        if isinstance(other, ApplicationID):
            return self.application_id == other.application_id
        elif isinstance(other, bytes):
            return self.application_id == other
        elif isinstance(other, str):
            return self.application_id == bytes.fromhex(other)
        elif isinstance(other, int):
            return self.application_id == bytes([other])[1:]
        return NotImplemented

    def __str__(self) -> str:
        """
        Get the Application ID as a hex string.
        """
        return self.application_id.hex(" ")
