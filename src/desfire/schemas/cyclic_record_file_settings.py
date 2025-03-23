from ..enums import DESFireCommunicationMode, DESFireFileType
from .file_permissions import FilePermissions
from .file_settings import FileSettings


class CyclicRecordFileSettings(FileSettings):
    def __init__(
        self,
        permissions: FilePermissions,
        record_size: int,
        max_records: int,
        current_records: int,
        encryption: DESFireCommunicationMode = DESFireCommunicationMode.PLAIN,
    ):
        """
        Initialize the CyclicRecordFileSettings object

        Args:
            permissions (FilePermissions): Permissions that should be applied to the file.
                Refer to the FilePermissions class for more information.
            record_size (int): Size of each record in bytes.
            max_records (int): Maximum number of records in the file.
            current_records (int): Current number of records in the file.
            encryption (DESFireCommunicationMode): Encryption mode that should be applied
                to the file. Can be plain (anyone can read/write), MACed (only authenticated users can read/write)
                or encrypted (only authenticated users can read/write).
        """

        super().__init__(DESFireFileType.MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP, permissions, encryption)

        self.record_size = record_size
        self.max_records = max_records
        self.current_records = current_records

    record_size: int
    max_records: int
    current_records: int

    def __repr__(self):
        """
        Returns a human readable representation of the file settings.
        """
        temp = super().__repr__()
        temp += f"Record size: {self.record_size}\r\n"
        temp += f"Max records: {self.max_records}\r\n"
        temp += f"Current records: {self.current_records}\r\n"

        return temp
