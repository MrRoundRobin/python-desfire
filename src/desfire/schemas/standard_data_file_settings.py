from ..enums import DESFireCommunicationMode, DESFireFileType
from .file_permissions import FilePermissions
from .file_settings import FileSettings


class StandardDataFileSettings(FileSettings):
    def __init__(
        self,
        permissions: FilePermissions,
        file_size: int,
        encryption: DESFireCommunicationMode = DESFireCommunicationMode.PLAIN,
    ):
        """
        Initialize the StandardDataFileSettings object

        Args:
            permissions (FilePermissions): Permissions that should be applied to the file.
                Refer to the FilePermissions class for more information.
            file_size (int): File size in bytes.
            encryption (DESFireCommunicationMode): Encryption mode that should be applied
                to the file. Can be plain (anyone can read/write), MACed (only authenticated users can read/write)
                or encrypted (only authenticated users can read/write).
        """

        super().__init__(DESFireFileType.MDFT_STANDARD_DATA_FILE, permissions, encryption)

        self.file_size = file_size

    file_size: int

    def __repr__(self):
        """
        Returns a human readable representation of the file settings.
        """
        temp = super().__repr__()
        temp += f"File size: {self.file_size}\r\n"

        return temp
