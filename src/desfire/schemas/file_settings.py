import struct

from ..enums import DESFireCommunicationMode, DESFireFileType
from .backup_data_file_settings import BackupDataFileSettings
from .cyclic_record_file_settings import CyclicRecordFileSettings
from .file_permissions import FilePermissions
from .liear_record_file_settings import LinearRecordFileSettings
from .standard_data_file_settings import StandardDataFileSettings
from .value_file_settings import ValueFileSettings


class FileSettings:
    def __init__(
        self,
        file_type: DESFireFileType,
        permissions: FilePermissions,
        encryption: DESFireCommunicationMode = DESFireCommunicationMode.PLAIN,
    ):
        """
        Initialize the FileSettings object

        Args:
            encryption (DESFireCommunicationMode | None, optional): Encryption mode that should be applied
                to the file. Can be plain (anyone can read/write), MACed (only authenticated users can read/write)
                or encrypted (only authenticated users can read/write).
            file_type (DESFireFileType | None, optional): Type of the file. Currently only standard files are supported.
            permissions (FilePermissions | None, optional): Permissions that should be applied to the file.
                Refer to the FilePermissions class for more information.
        """
        self.encryption = encryption
        self.file_type = file_type
        self.permissions = permissions

    encryption: DESFireCommunicationMode
    file_type: DESFireFileType
    permissions: FilePermissions

    @classmethod
    def parse(
        cls, data: bytes
    ) -> (
        BackupDataFileSettings
        | CyclicRecordFileSettings
        | LinearRecordFileSettings
        | StandardDataFileSettings
        | ValueFileSettings
    ):
        """
        Takes raw data from command 0xF5 (get file settings) and parses it into a FileSettings object.

        Example of a raw data from command 0xF5 (get file settings on a standard data file):

        ```
        00 03 00 23 08 00 00
        ^^ ^^ ^^^^^ ^^^^^^^^
        |  |  |     |
        |  |  |     ^ File Size (3 bytes)
        |  |  ^ File Permissions (2 bytes)
        |  ^ Communication / Encryption mode (1 byte)
        ^ File Type (1 byte)
        ```

        File permissions are 4 bits each:
            - 0b - 3b: Change Permission key
            - 4b - 7b: Read-Write Permission key
            - 8b - 11b: Write Permission key
            - 12b - 15b: Read Permission key

        There are four other file types that are not implemented yet.
        """

        file_type = DESFireFileType(data[0])

        file_settings = None

        if file_type == DESFireFileType.MDFT_STANDARD_DATA_FILE:
            file_settings = StandardDataFileSettings(
                encryption=DESFireCommunicationMode(data[1]),
                permissions=FilePermissions.parse(data[2:4]),
                file_size=struct.unpack("<I", data[4:7] + b"\0")[0],
            )
        elif file_type == DESFireFileType.MDFT_BACKUP_DATA_FILE:
            file_settings = BackupDataFileSettings(
                encryption=DESFireCommunicationMode(data[1]),
                permissions=FilePermissions.parse(data[2:4]),
                file_size=struct.unpack("<I", data[4:7] + b"\0")[0],
            )
        elif file_type == DESFireFileType.MDFT_VALUE_FILE_WITH_BACKUP:
            file_settings = ValueFileSettings(
                encryption=DESFireCommunicationMode(data[1]),
                permissions=FilePermissions.parse(data[2:4]),
                min_value=struct.unpack("<I", data[4:8])[0],
                max_value=struct.unpack("<I", data[8:12])[0],
                value=struct.unpack("<I", data[12:16])[0],
                backup_value=bool(struct.unpack("<B", data[16])[0]),
            )
        elif file_type == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
            file_settings = LinearRecordFileSettings(
                encryption=DESFireCommunicationMode(data[1]),
                permissions=FilePermissions.parse(data[2:4]),
                record_size=struct.unpack("<I", data[4:7] + b"\0")[0],  # Check endianess
                max_records=struct.unpack("<I", data[7:10] + b"\0")[0],
                current_records=struct.unpack("<I", data[10:14] + b"\0")[0],
            )
        elif file_type == DESFireFileType.MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
            file_settings = CyclicRecordFileSettings(
                encryption=DESFireCommunicationMode(data[1]),
                permissions=FilePermissions.parse(data[2:4]),
                record_size=struct.unpack("<I", data[4:7] + b"\0")[0],  # Check endianess
                max_records=struct.unpack("<I", data[7:10] + b"\0")[0],
                current_records=struct.unpack("<I", data[10:14] + b"\0")[0],
            )
        else:
            raise NotImplementedError(f"Filetype {data[0:1].hex()} is currently not supported.")

        return file_settings

    def __repr__(self):
        """
        Returns a human readable representation of the file settings.
        """
        temp = " ----- FileSettings ----\r\n"
        temp += f"File type: {self.file_type.name}\r\n"
        temp += f"Encryption: {self.encryption.name}\r\n"
        temp += f"Permissions: \r\n{repr(self.permissions)}\r\n"

        return temp
