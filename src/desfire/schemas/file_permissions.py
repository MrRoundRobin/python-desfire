class FilePermissions:
    def __init__(self, read_key: int = 0, write_key: int = 0, read_write_key: int = 0, change_key: int = 0):
        """
        This class represents the permissions of a file on a DESFire card.

        Each permission represents a key number within the application that should be used
        to obtain the corresponding access rights. Each of them is a 4-bit value, where the
        bits are as follows:

        - 0x0 - 0xD   Key number that should be used to obtain the corresponding access rights
        - 0xE         No restrictions (free access)
        - 0xF         No Access allowed
        """

        if (read_key & 0xF0) or (write_key & 0xF0) or (read_write_key & 0xF0) or (change_key & 0xF0):
            raise ValueError("Key values must be in the range of 0x00 to 0x0F")

        self.read_access = read_key & 0x0F
        self.write_access = write_key & 0x0F
        self.read_and_write_access = read_write_key & 0x0F
        self.change_access = change_key & 0x0F

    @classmethod
    def parse(cls, data: bytes) -> "FilePermissions":
        """
        Parse the raw data into a FilePermissions object. Raw data is two bytes, split into 4-bit values.

        Source:
        https://github.com/EsupPortail/esup-nfc-tag-server/blob/295aed8cbcf09323cf859fa5753b5482ce7eee3c/src/main/java/org/esupportail/nfctag/service/desfire/DESFireEV1Service.java#L1889

        - File permissions are (MSB = start):
        - - 0b - 3b: Read-Write key
        - - 4b - 7b: Change permission key
        - - 8b - 11b: Read key
        - - 12b - 15b: Write key

        Example Data: `0x00 0x23`

        ```
        0000 0000 0010 0011
        ^^^^ ^^^^ ^^^^ ^^^^
        RW   C    R    W
        ```
        """

        return FilePermissions(
            read_key=(data[1] >> 4) & 0x0F,
            write_key=data[1] & 0x0F,
            read_write_key=(data[0] >> 4) & 0x0F,
            change_key=data[0] & 0x0F,
        )

    def serialize(self) -> bytes:
        """
        Returns the permissions as a list of two bytes.
        """
        return bytes(
            [
                ((self.read_and_write_access & 0x0F) << 4) | (self.change_access & 0x0F),
                ((self.read_access & 0x0F) << 4) | (self.write_access & 0x0F),
            ]
        )

    def __repr__(self):
        """
        Returns a human readable representation of the file permissions.
        """
        temp = "FilePermissions:\r\n\r\n"
        temp += f" {self.read_and_write_access:02} | {self.change_access:02} | {self.read_access:02} | {self.write_access:02}\r\n"
        temp += "----+----+----+----\r\n"
        temp += " RW | C  | R  | W\r\n"

        return temp
