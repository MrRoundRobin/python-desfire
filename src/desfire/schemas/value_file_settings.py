from ..enums import DESFireCommunicationMode, DESFireFileType
from .file_permissions import FilePermissions
from .file_settings import FileSettings


class ValueFileSettings(FileSettings):
    def __init__(
        self,
        permissions: FilePermissions,
        current_value: int,
        min_value: int,
        max_value: int,
        limited_credit: bool = False,
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

        self.current_value = current_value
        self.min_value = min_value
        self.max_value = max_value
        self.limited_credit = limited_credit

    current_value: int
    min_value: int
    max_value: int
    limited_credit: bool

    def __repr__(self):
        """
        Returns a human readable representation of the file settings.
        """
        temp = super().__repr__()
        temp += f"Current Value: {self.current_value}\r\n"
        temp += f"Min Value: {self.min_value}\r\n"
        temp += f"Max Value: {self.max_value}\r\n"
        temp += f"Limited Credit: {self.limited_credit}\r\n"

        return temp
