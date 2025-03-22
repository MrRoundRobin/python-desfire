import logging
import struct

from Crypto.Random import get_random_bytes

from .devices.base import Device
from .enums import DESFireCommand, DESFireCommunicationMode, DESFireKeySettings, DESFireKeyType, DESFireStatus
from .exceptions import DESFireAuthException, DESFireCommunicationError, DESFireException
from .key import DESFireKey
from .schemas import CardVersion, FileSettings, KeySettings
from .util import CRC32, xor_lists

logger = logging.getLogger(__name__)


class DESFire:
    """
    This is the main class of this library, facilitating communication with the DESFire card.
    """

    is_authenticated: bool = False
    session_key: DESFireKey | None = None
    max_frame_size: int = 60
    last_selected_application: bytes | None = None
    last_auth_key_id: int | None = None

    def __init__(self, device: Device):
        """
        Initializes a new DESfire object which can be used to interact with the card.
        Requires an initialized PCSC device object, refer to the examples for details and uage examples.

        Args:
            device (Device): Initialized PCSC device object
        """
        self.device = device
        logger.info("DESFire object initialized")

    #
    # Internal Methods
    #

    def _communicate(self, apdu_cmd: bytes, native: bool = True, af_passthrough: bool = False) -> bytes:
        """
        Communicate with a NFC tag. Send in outgoing request and wait for a card reply.

        Args:
            apdu_cmd (bytes): Outgoing APDU command as bytes
            native (bool, optional): True indicates that DESfire native commands are used,
                otherwise ISO 7816 APDUs are used
            af_passthrough (bool, optional): If true, a 0xAF response (indicating more incoming data) is instantly
                returned to the callee instead of trying to handle it internally

        Raises:
            DESFireCommunicationError: Used to indicate a communication error with the card

        Returns:
            bytes: Bytes received from the card
        """

        result: bytearray = bytearray()
        additional_data: bool = True

        # Loop until all data is received
        while additional_data:
            # Send the APDU command to the card
            logger.debug("Running APDU command, sending: %s", apdu_cmd.hex(" "))
            resp = self.device.transceive(apdu_cmd)
            logger.debug("Received APDU response: %s", resp.hex(" "))

            # DESfire native commands are used
            if native:
                status = resp[0]
                # Check for known error interpretation
                if status == 0xAF:
                    if af_passthrough:
                        logger.debug("More data present (indicated by 0xAF), returning response to callee")
                        additional_data = False
                    else:
                        # Need to loop more cycles to fill in receive buffer
                        logger.debug("More data present (indicated by 0xAF), sending continue command")
                        additional_data = True
                        apdu_cmd = self._command(DESFireCommand.ADDITIONAL_FRAME)  # Continue
                elif status != 0x00:
                    try:
                        error_description = DESFireStatus(status).name
                    except ValueError:
                        error_description = f"Unknown error, status {status}"
                    logger.error("Received error from card: %s", error_description)
                    raise DESFireCommunicationError(error_description, status)
                else:
                    additional_data = False

                result.extend(resp[1:])
            else:  # If commands are wrapped in ISO 7816-4 APDU Frames, SW1 must be 0x91
                if resp[-2] != 0x91:
                    raise DESFireCommunicationError(
                        "Received invalid response for command using native communication", resp[-2:]
                    )
                # Possible status words:
                # https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
                # status = resp[-1]
                result.extend(resp[0:-2])

        return bytes(result)

    @classmethod
    def _add_padding(cls, data: bytes, blocksize: int = 16) -> bytes:
        """
        Adds padding to the data to make it a multiple of the cipher block size

        Padding is 0x80 once followed by 0x00 bytes until the block size is reached.

        @See https://stackoverflow.com/a/23704425/1627106
        Moreover, be careful about the way you have to do the padding.
        The DESFire EV1 datasheet is ambiguous on that. While the section
        on AES encryption suggests that CMAC padding should always be used
        together with AES, the section on padding states that commands with
        known data length should be padded with all zeros, while commands with
        unknown data length should be padded with 0x80 followed by zeros.
        Finally the documentation on the write command explicitly states
        that the write command should be padded with all zeros for encryption
        (and that's what you are supposed to do).
        """
        # TODO: Check if this is correct

        if len(data) % blocksize == 0:
            return data

        padding = blocksize - (len(data) % blocksize)
        logger.debug(f"Adding padding of {padding} bytes to the data.")
        logger.debug(f"Original Data: {data.hex(' ')}")
        padded_data = data + b"\x80" + bytes(padding - 1)
        logger.debug(f"Padded Data: {padded_data.hex(' ')}")

        return padded_data

    @classmethod
    def _command(cls, command: DESFireCommand, *parameters: bytes | int) -> bytes:
        """
        Concatenate the command and parameters into a single list that can be sent to the card.
        """
        r_val = bytearray([command.value])

        for param in parameters:
            if param is int:
                r_val.append(param)
            elif isinstance(param, bytes):
                r_val.extend(param)

        return bytes(r_val)

    def _preprocess(
        self,
        apdu_cmd: bytes,
        tx_mode: DESFireCommunicationMode,
        disable_crc: bool = False,
        encryption_offset: int = 1,
    ) -> bytes:
        """
        Preprocess the command before sending it to the card. This includes adding the padding and the CRC if needed.
        """

        logger.debug(f"Preprocessing command {apdu_cmd.hex(' ')}")

        # If not authenticated, we don't need to do anything
        if not self.is_authenticated:
            logger.debug("Not authenticated, skipping preprocessing")
            return apdu_cmd

        assert self.session_key is not None

        # Preprocess the command
        if tx_mode == DESFireCommunicationMode.PLAIN:
            # We don't do anything with the CMAC, but it does update the IV for future crypto operations
            logger.debug("Calculating CMAC for data simply to update IV")
            self.session_key.calculate_cmac(apdu_cmd)
            return apdu_cmd
        elif tx_mode == DESFireCommunicationMode.CMAC:
            # Calculate the CMAC and append it to the command
            logger.debug("Calculating CMAC for data")
            tx_cmac = self.session_key.calculate_cmac(apdu_cmd)
            logger.debug("CMAC has been calculated to be: " + tx_cmac.hex(" "))
            # Only the last 8 bytes of the CMAC are used
            return apdu_cmd + tx_cmac[-8:]
        elif tx_mode == DESFireCommunicationMode.ENCRYPTED:
            assert self.session_key.cipher_block_size is not None

            logger.debug("Command requires data to be encrypted. Calculating CRC and encrypting message")
            logger.debug("Original data: " + apdu_cmd.hex(" "))

            # Encrypt the command + data
            resp_data = self.session_key.encrypt_msg(apdu_cmd, disable_crc=disable_crc, offset=encryption_offset)
            logger.debug("Encrypted data: " + resp_data.hex(" "))

            # Update IV to the last block of the encrypted data
            self.session_key.set_iv(resp_data[-self.session_key.cipher_block_size :])

            # Return encrypted data
            return resp_data
        else:
            logger.error("Invalid communication mode while trying to preprocess command")
            raise Exception("Invalid communication mode")

    def _postprocess(self, response: bytes, rx_mode: DESFireCommunicationMode) -> bytes:
        """
        Postprocess the response from the card.
        """

        logger.debug(f"Postprocessing PICC response {response.hex(' ')}")

        # PLAIN response is only possible if we're not authenticated
        if rx_mode == DESFireCommunicationMode.PLAIN:
            logger.debug("Response is plain, returning as is")
            return response
        # CMAC response is only possible if we're authenticated
        elif rx_mode == DESFireCommunicationMode.CMAC:
            """
            The CMAC is calculated over the payload of the response (i.e after the status byte) and then the status byte
            appended to the end. If the response is multiple parts then the payload of these parts are concatenated
            (without the AF status byte) and the final status byte added to the end.
            """
            logger.debug("Response is CMAC protected, we need to verify it")
            assert self.session_key is not None

            # Calculate the CMAC of the last 8 bytes of the response and append status code
            cmac_data = response[:-8] + b"\x00"  # Status code of a successful command is always 0x00

            logger.debug("Calculating CMAC for data: " + cmac_data.hex(" "))
            calculated_cmac = self.session_key.calculate_cmac(cmac_data)[:8]

            logger.debug("RXCMAC      : " + response[-8:].hex(" "))
            logger.debug("RXCMAC_CALC : " + calculated_cmac.hex(" "))

            if response[-8:] != calculated_cmac:
                logger.warning("CMAC verification failed!")
                raise Exception("CMAC verification failed!")

            return response[:-8]
        # ENCRYPTED response is only possible if we're authenticated
        elif rx_mode == DESFireCommunicationMode.ENCRYPTED:
            """
            The response is encrypted using the session key. The response is padded with 0x80 followed by 0x00 bytes
            until the end of the block. The IV is updated with the last block of the encrypted data.
            """
            logger.debug("Response is encrypted, decrypting")
            assert self.session_key is not None
            assert self.session_key.cipher_block_size is not None

            # Decrypt the response
            logger.debug("Encrypted response: " + response.hex(" "))
            padded_response = self._add_padding(response)
            logger.debug("Padded response: " + padded_response.hex(" "))
            decrypted_response = self.session_key.decrypt(padded_response)
            logger.debug("Decrypted response: " + decrypted_response.hex(" "))

            # Update IV to the last block of the encrypted data
            self.session_key.set_iv(response[-self.session_key.cipher_block_size :])

            # TODO: Check if this is a good idea, what is with the 0x80 padding?
            # Remove all null bytes from the end

            decrypted_response = decrypted_response.rstrip(b"\x00")

            logger.debug("Decrypted response (trimmed): " + decrypted_response.hex(" "))

            # Check if the CRC is correct - Status byte is appended to the data before CRC calculation
            logger.debug("Verifying CRC checksum")
            crc_bytes = 4  # 2 (CRC16) is only needed for legacy authentication, which we do not support (only ISO+AES)
            received_crc = decrypted_response[-crc_bytes:]
            logger.debug("Received CRC  : " + received_crc.hex(" "))
            calculated_crc = CRC32(decrypted_response[:-crc_bytes] + [0x00])
            logger.debug("Calculated CRC: " + calculated_crc.hex(" "))

            if received_crc != calculated_crc:
                logger.warning(
                    f"CRC verification failed! (received: {received_crc.hex(' ')},"
                    f" calculated: {calculated_crc.hex('')})"
                )
                raise Exception("CRC verification failed!")

            # Remove the CRC from the response
            response = decrypted_response[:-crc_bytes]

        return response

    def _transceive(
        self,
        apdu_cmd: bytes,
        tx_mode: DESFireCommunicationMode,
        rx_mode: DESFireCommunicationMode,
        af_passthrough: bool = False,
        disable_crc: bool = False,
        encryption_offset: int = 1,
    ) -> bytes:
        """
        Communicate with the card. This is the main function that sends the APDU command and performs
        neccessary pre- and postprocessing of the data. It also handles the CMAC calculation and
        encryption/decryption of the communication if needed.
        """

        # Check for existing of session key if needed
        if tx_mode != DESFireCommunicationMode.PLAIN or rx_mode != DESFireCommunicationMode.PLAIN:
            if not self.is_authenticated:
                logger.error("Cant perform crypto operations without authentication!")
                raise Exception("Cant perform crypto operations without authentication!")

        # Preprocess the command, includes CMAC calculation and encryption
        apdu_cmd = self._preprocess(apdu_cmd, tx_mode, disable_crc, encryption_offset)

        # Send the command to the card, note that this command will raise an exception if the card returns an error
        response = self._communicate(apdu_cmd, af_passthrough=af_passthrough)

        # Postprocess the response
        return self._postprocess(response, rx_mode)

    #
    # Public Methodds
    #

    # Authentication

    def authenticate(self, key_id: int, key: DESFireKey, challenge: bytes | None = None):
        """
        Authenticate against the currently selected application with key_id.
        If no application has been selected before, the default (master) application is used, which is `0x00`.
        In this case, only key `0x00` can be used for authentication.

        Authentication:
            Not required.

        Args:
            key_id (int): Key ID to authenticate with. Must be `0x00` if no application is selected.
            key (DESFireKey): Instance of the DESFireKey class containing the key data that is used to authenticate.
            challenge (bytes | None, optional): During the handshake process,
                the card will respond with a randomly generated challenge and then expects this device to answer with a
                random challenge as well. This challenge can be provided, it is not recommended though.

        Raises:
            DESFireException: if an invalid configuration is provided
            DESFireAuthException: If authentication fails
        """

        assert key.cipher_block_size is not None
        logger.debug("Authenticating against PICC")
        self.is_authenticated = False

        # Determine the authentication command based on the key type
        if key.key_type == DESFireKeyType.DF_KEY_AES:
            logger.debug(f"Authenticating using AES authentication scheme and key_id {key_id}")
            cmd = DESFireCommand.AUTHENTICATE_AES
            params = key_id
        elif key.key_type == DESFireKeyType.DF_KEY_2K3DES or key.key_type == DESFireKeyType.DF_KEY_3K3DES:
            logger.debug(f"Authenticating using ISO authentication scheme and key_id {key_id}")
            cmd = DESFireCommand.AUTHENTICATE_ISO
            params = key_id
        else:
            logger.error("Invalid key type has been provided.")
            raise DESFireException("Invalid key type has been provided.")

        # First part of three way handshake - Initial authentication and retrieve RND_B from card
        # AF_Passthrough is required as the card will respond with 0xAF as challenge response
        RndB_enc = self._transceive(
            self._command(cmd, params),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
            af_passthrough=True,
        )
        logger.debug("Encrypion: Random B (enc):" + RndB_enc.hex(" "))

        # Check if the key type is correct
        if (key.key_type == DESFireKeyType.DF_KEY_3K3DES or key.key_type == DESFireKeyType.DF_KEY_AES) and len(
            RndB_enc
        ) != 16:
            logger.warning(
                "Encrypion:  Card expects a different key type. "
                "(enc B size is less than the blocksize of the key you specified)"
            )
            raise DESFireException(
                "Card expects a different key type. (enc B size is less than the blocksize of the key you specified)"
            )

        # Reinitalize the cipher object of the key
        key.cipher_init()

        # Decrypt the RndB using the provided master key
        RndB = key.decrypt(RndB_enc)
        logger.debug("Encrypion: Random B (dec): " + RndB.hex(" "))

        # Rotate RndB to the left by one byte
        RndB_rot = RndB[1:] + RndB[0:1]
        logger.debug("Encrypion: Random B (dec, rot): " + RndB_rot.hex(" "))

        # Challenge can be either provided externally, or generated randomly
        if challenge is not None:
            RndA = challenge
        else:
            RndA = get_random_bytes(len(RndB))
        logger.debug("Encrypion: Random A: " + RndA.hex(" "))

        # Concatenate RndA and RndB_rot and encrypt it with the master key
        RndAB = RndA + RndB_rot
        logger.debug("Encrypion: Random AB: " + RndAB.hex(" "))
        key.set_iv(RndB_enc)
        RndAB_enc = key.encrypt(RndAB)
        logger.debug("Encrypion: Random AB (enc): " + RndAB_enc.hex(" "))

        # Send the encrypted RndAB to the card, it should reply with a positive result
        RndA_enc = self._transceive(
            self._command(DESFireCommand.ADDITIONAL_FRAME, RndAB_enc),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )

        # Verify that the response matches our original challenge
        logger.debug("Encrypion: Random A (enc): " + RndA_enc.hex(" "))
        key.set_iv(RndAB_enc[-key.cipher_block_size :])
        RndA_dec = key.decrypt(RndA_enc)
        logger.debug("Encrypion: Random A (dec): " + RndA_dec.hex(" "))
        RndA_dec_rot = RndA_dec[-1:] + RndA_dec[0:-1]
        logger.debug("Encrypion: Random A (dec, rot): " + RndA_dec_rot.hex(" "))

        if RndA != RndA_dec_rot:
            raise DESFireAuthException("Authentication FAILED!")

        logger.info("Authentication successful")
        self.is_authenticated = True
        self.last_auth_key_id = key_id

        logger.debug("Encrypion: Calculating Session key")
        session_key_bytes = RndA[:4]
        session_key_bytes += RndB[:4]
        if key.key_size > 8:
            if key.key_type == DESFireKeyType.DF_KEY_2K3DES:
                session_key_bytes += RndA[4:8]
                session_key_bytes += RndB[4:8]
            elif key.key_type == DESFireKeyType.DF_KEY_3K3DES:
                session_key_bytes += RndA[6:10]
                session_key_bytes += RndB[6:10]
                session_key_bytes += RndA[12:16]
                session_key_bytes += RndB[12:16]
            elif key.key_type == DESFireKeyType.DF_KEY_AES:
                session_key_bytes += RndA[12:16]
                session_key_bytes += RndB[12:16]

        if key.key_type in (DESFireKeyType.DF_KEY_2K3DES, DESFireKeyType.DF_KEY_3K3DES):
            session_key_bytes = bytes(a & 0b11111110 for a in session_key_bytes)

        ## now we have the session key, so we reinitialize the crypto part of the key
        key.set_key(session_key_bytes)
        key.generate_cmac()
        key.clear_iv()

        # Store the session key
        self.session_key = key

    #
    ## Card related
    #

    def get_real_uid(self) -> bytes:
        """
        Depending on the card configuration, the UID returned using `get_card_version` can be random.
        This command returns the real UID of the card.

        Authentication:
            Required

        Raises:
            DESFireException: if an invalid configuration is provided

        Returns:
            bytes: 7 byte UID of the card
        """
        logger.info(f"Executing command: get_real_uid (0x{DESFireCommand.GET_CARD_UID.value:02x})")

        if not self.is_authenticated:
            logger.warning("Tried to get real UID without authentication")
            raise DESFireException("Not authenticated!")

        return self._transceive(
            self._command(DESFireCommand.GET_CARD_UID),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.ENCRYPTED,
        )

    def get_card_version(self) -> CardVersion:
        """
        Gets the card version data, which contains information about the card such as the UID, batch number, etc.

        Authentication:
            Not required.

        !!! warning
            DESFire cards have a security feature called "Random UID" which can be activated.
            If active, the PICC will will return a random UID each time you call this function.

        Returns:
            CardVersion: An instance of the CardVersion schema containing the card version information

        Raises:
            DESFireException: if an invalid configuration is provided
        """
        logger.info(f"Executing command: get_card_version (0x{DESFireCommand.GET_VERSION.value:02x})")

        raw_data = self._transceive(
            self._command(DESFireCommand.GET_VERSION),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        return CardVersion(raw_data)

    def format_card(self):
        """
        Formats the card, deleting all keys, applications and files on the card.

        Authentication:
            Authentication using the application `0x00` master key (key id `0x00`) is required

        !!! warning
            THIS COMPLETELY WIPES THE CARD AND RESETS IT TO A BLANK CARD!!

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to format card without authentication")
            raise DESFireException("Not authenticated!")

        logger.info(f"Executing command: format_card (0x{DESFireCommand.FORMAT_PICC.value:02x})")

        self._transceive(
            self._command(DESFireCommand.FORMAT_PICC),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )

    #
    ## Key Related
    #

    def get_key_setting(self) -> KeySettings:
        """
        Gets the key settings for the master key of the application currently selected.

        It returns two bytes, where the first byte contains the key settings for the current application
        as described in the change_key_settings method. The second byte is structured as follows:

        ```
        KKKK|DDDD
        7       0
        ```

        - K: Determines the key type as defined in the DESFireKeyType enum
        - D: Maximum number of keys that are allowed by the application. Always 1 for the main appliction (0x0).

        Authentication:
            Not required.

        Returns:
            KeySettings: An instance of the KeySettings schema containing the key settings. Can be
                used to authenticate using this key or another key of the same application.
        """

        logger.info(f"Executing command: get_key_setting (0x{DESFireCommand.GET_KEY_SETTINGS.value:02x})")

        resp = self._transceive(
            self._command(DESFireCommand.GET_KEY_SETTINGS),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

        res = KeySettings(
            application_id=self.last_selected_application or b"\0\0\0",
            key_type=DESFireKeyType(resp[1] & 0xF0),  # Only interested in first 4 bits of the second byte
            max_keys=resp[1] & 0x0F,  # Only interested in last 4 bits of the second byte
            settings=[],
        )

        res.parse_settings(resp[0])
        return res

    def get_key_version(self, key_number: int) -> int:
        """
        Returns the version of the key, which is a one byte that can be set when the key is created.
        It is typically used to distinguish between different versions of the same key in use.

        Authentication:
            Required.

        Args:
            key_number (int): Number of the key to get the version from. Must be between 0x00 and 0x0D.

        Returns:
            int: Single byte containing the custom version information.
        """

        logger.info(
            f"Executing command: get_key_version (0x{DESFireCommand.GET_KEY_VERSION.value:02x}) for key {key_number:x}"
        )

        raw_data = self._transceive(
            self._command(DESFireCommand.GET_KEY_VERSION, key_number),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        assert len(raw_data) == 1
        return raw_data[0]

    def change_key_settings(self, new_settings: list[DESFireKeySettings]):
        """
        Changes key settings for the application currently selected.

        Authentication:
            Required.

        !!! note "Key settings details"
            Note that the key settings depend on the application that is currently selected.
            Settings are represented as one byte, which is structures as follows:

            ```
            FFFF | AAAA
            0         7
            ```

            The first four bits are flags which control certain settings, such as whether creating and deleting
            applications requires authentication or not. Refer to DESFireKeySettings for more information.

            !!! warning
                Bit 3 (frozen settings) cannot be cleared once it is set.

            The last four bits are only relevant for applications and determine how keys can be changed. Values below
            are represented in hex:

            - 0x0 - 0xD: This specific key can change any key
            - 0xE: Only the key that was used for authentication can be changed
            - 0xF: All keys are locked (except master key, this is controlled by a flag as documented above)

        Example:

        You can use the provided enum (DESFireKeySettings) to set the key settings. For example, to allow
        a change of keys with the app master key, you can use the following code:

        ```python
        change_key_settings([DESFireKeySettings.KS_CHANGE_KEY_WITH_MK])
        ```

        Args:
            new_settings (list[DESFireKeySettings]): List of key settings to apply to the application.
                Refer to the DESFireKeySettings enum for possible values.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to change key settings without authentication")
            raise DESFireException("Not authenticated.")

        logger.info(f"Executing command: change_key_settings (0x{DESFireCommand.CHANGE_KEY_SETTINGS.value:02x})")

        key_settings = KeySettings(settings=new_settings)

        # logger.debug('Changing key settings to %s' %('|'.join(a.name for a in newKeySettings),))
        self._transceive(
            self._command(DESFireCommand.CHANGE_KEY_SETTINGS, key_settings.get_settings()),
            DESFireCommunicationMode.ENCRYPTED,
            DESFireCommunicationMode.CMAC,
        )

    def change_key(self, key_id: int, current_key: DESFireKey, new_key: DESFireKey, new_key_version: int | None = None):
        """
        Changes a key from a current value to a new value. If the key is the one currently used for authentication,
        the authentication session is invalidated.

        Authentication:
            Required.

        Args:
            key_id (int): ID of the key to change. Can also be the key that is currently used for authentication.
            current_key (DESFireKey): Key that is currently in use.
            new_key (DESFireKey): New key to set.
            new_key_version (int | None, optional): Optionally you can set a version for the new key. It is
                for information purposes only and can be used to distinguish between different versions of a key.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to change key without authentication")
            raise DESFireException("Not authenticated!")

        logger.info(f"Executing command: change_key (0x{DESFireCommand.CHANGE_KEY.value:02x}) for key {key_id:x}")

        # If we're changing the key we're authenticated with, the message format
        # is different than if we're changing a different key.
        is_same_key = key_id == self.last_auth_key_id
        if is_same_key:
            logger.debug("Changing the key we're authenticated with, need to re-authenticate after")
        else:
            logger.debug("Changing a different key, no need to re-authenticate")

        # Calculate the key number parameter
        # The key_no parameter has 4 bits (MSB, key type) + 4 bits (LSB, key number).
        # The type of key can only be changed for the PICC master key
        # Applications must define their key type in create_application()
        key_number = key_id & 0x0F
        if self.last_selected_application == b"\0":
            key_number = key_number | current_key.key_type.value
            logger.debug(f"Key number parameter calculated: {key_number:02x}")

        # Data to transmit depends on whether we're changing the PICC master key or an application key
        # and whether we're changing the key we're authenticated with or a different one
        data = bytearray(self._command(DESFireCommand.CHANGE_KEY, key_number))

        # The following can only apply to application keys, as the PICC has only one key (0x00).
        if not is_same_key:
            # If we're changing a different key, new key data is the new key XORed with the old key
            # If we're changing the key type at the same time, we need to XOR the new key with the old key twice
            if len(new_key.get_key()) > len(current_key.get_key()):
                logger.debug("New key is longer than the current key, XORing current key twice")
                data.extend(xor_lists(new_key.get_key(), current_key.get_key() * 2))
            else:
                logger.debug("New key is shorter than the current key, XORing current key")
                data.extend(xor_lists(new_key.get_key(), current_key.get_key()))
        else:
            # If we're changing the key we're authenticated with, new key data is the new key
            data.extend(new_key.get_key())

        # If the new key is AES, we need to append the key version
        if new_key.key_type == DESFireKeyType.DF_KEY_AES:
            assert new_key_version is not None
            data.append(new_key_version)

        # Regular CRC32 of the data is always appended
        data.extend(CRC32(bytes(data)))

        # If we're changing a different key, CRC32 of the new key is appended as well
        if not is_same_key:
            logger.debug("Changing a different key, appending CRC32 of new key as well")
            data.extend(CRC32(new_key.get_key()))

        # Send the command - auth session is invalidated if we chnge the key we're authenticated with
        self._transceive(
            bytes(data),
            tx_mode=DESFireCommunicationMode.ENCRYPTED,
            rx_mode=DESFireCommunicationMode.PLAIN if is_same_key else DESFireCommunicationMode.CMAC,
            disable_crc=True,
            encryption_offset=2,
        )

        # If we changed the currently active key, then re-auth is needed!
        if is_same_key:
            logger.info("Key of authentication change successful, re-authentication is needed")
            self.is_authenticated = False
            self.session_key = None

    def change_default_key(self, new_key: DESFireKey, key_version: int = 0):
        """
        Allows changing the default key that is used as application master key when creating new applications.

        Authentication:
            Required.

        Args:
            new_key (DESFireKey): New key to set as the default key.
            key_version (int, optional): Key version to set when using this key.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.warning("Tried to change default key without authentication")
            raise DESFireException("Not authenticated!")

        logger.info(f"Executing command: change_default_key (0x{DESFireCommand.SET_CONFIGURATION.value:02x}01)")

        # 0x5C is related to the card configuration, 0x01 is the default key
        data = self._command(DESFireCommand.SET_CONFIGURATION, 0x01)

        # Append key data and pad it to 24 bytes key length
        data += new_key.get_key().ljust(24, b"\0")

        # Append key version
        data += bytes([key_version])

        # Send the command, CRC is appended automatically but we need to exclude the first two bytes from encryption
        self._transceive(
            data,
            tx_mode=DESFireCommunicationMode.ENCRYPTED,
            rx_mode=DESFireCommunicationMode.CMAC,
            encryption_offset=2,
        )

    #
    ## Application related
    #

    def get_application_ids(self) -> list[bytes]:
        """
        Lists all application currently configured on the card.

        Authentication:
            Not required.

        Returns:
            list[bytes]: List of application IDs, in a 3 bytes
        """
        logger.info(f"Executing command: get_application_ids (0x{DESFireCommand.GET_APPLICATION_IDS.value:02x})")

        raw_data = self._transceive(
            self._command(DESFireCommand.GET_APPLICATION_IDS),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        logger.debug(f"Raw data: {raw_data.hex(' ')}")

        # Parse App data, each of them is 3 bytes long
        apps = []
        for i in range(0, len(raw_data), 3):
            appid = raw_data[i : i + 3]
            logger.debug(f"Found application with AppID {appid.hex(' ')}")
            apps.append(appid)

        logger.debug(f"Found {len(apps)} applications")
        return apps

    def select_application(self, appid: bytes):
        """
        Choose application on a card on which all the following commands will apply.

        Authentication:
            MAY be required depending on the application settings.

        Args:
            appid (bytes): ID of the application.
        """

        logger.info(f"Selecting application with ID {appid.hex(' ')}")

        #  As application selection invalidates auth, there's no need to use CMAC
        self._transceive(
            self._command(DESFireCommand.SELECT_APPLICATION, appid),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )

        # if new application is selected, authentication needs to be carried out again
        logger.debug("Application selected, new authentication is needed")
        self.is_authenticated = False
        self.last_auth_key_id = None
        self.last_selected_application = appid

    def create_application(self, appid: bytes, keysettings: KeySettings, keycount: int):
        """
        Creates a new application on the card with the specified settings. The key settings provided are
        applied to the master key of the application.

        Authentication:
            Required.

        Args:
            appid (bytes): 3 byte application ID.
            keysettings (KeySettings): Key settings to apply to the application.
            keycount (int): Number of keys that can be stored in the application.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.error("Tried to create application without authentication")
            raise DESFireException("Not authenticated!")

        if not keysettings.settings or not keysettings.key_type:
            logger.error("Key type and key settings must be set in the KeySettings object.")
            raise DESFireException("The key type and key settings must be set in the KeySettings object.")

        if not 0 <= keycount <= 14:
            logger.error("Key count must be between 0 and 14.")
            raise DESFireException("Key count must be between 0 and 14.")

        logger.info(f"Creating application with ID: {appid.hex(' ')}, ")

        # Structure of the APDU:
        # 0xCA + AppID (3 bytes) + key settings (1 byte) + app settings (4 MSB = key type, 4 LSB = key count)

        self._transceive(
            self._command(
                DESFireCommand.CREATE_APPLICATION,
                appid,
                keysettings.get_settings(),
                keycount | keysettings.key_type.value,
            ),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC,
        )
        logger.debug("Application created successfully")

    def delete_application(self, appid: bytes):
        """
        Deletes the application specified by appid

        Authentication:
            Required.

        Args:
            appid (bytes): 3 byte application ID.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.is_authenticated:
            logger.error("Tried to delete application without authentication")
            raise DESFireException("Not authenticated!")

        logger.info("Deleting application for ID %s", appid.hex(" "))

        self._transceive(
            self._command(DESFireCommand.DELETE_APPLICATION, appid),
            DESFireCommunicationMode.CMAC,
            DESFireCommunicationMode.CMAC,
        )

    #
    ## File related
    #

    def get_file_ids(self) -> list[int]:
        """
        Lists all files belonging to the application currently selected. `select_application` needs to be called first

        Authentication:
            MAY be required depending on the application settings.

        Returns:
            List of file IDs in the application

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            logger.error("Tried to get file IDs without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        logger.info(f"Executing command: get_file_ids (0x{DESFireCommand.GET_FILE_IDS.value:02x})")

        raw_data = self._transceive(
            self._command(DESFireCommand.GET_FILE_IDS),
            tx_mode=DESFireCommunicationMode.PLAIN,
            rx_mode=DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

        # Parse the raw data
        if len(raw_data) == 0:
            logger.debug("No files found")
        else:
            logger.debug(f"File ids: {raw_data.hex(' ')}")

        return [int(byte) for byte in raw_data]

    def get_file_settings(self, file_id: int) -> FileSettings:
        """
        Gets file settings for the file identified by file_id. `select_application` must be called first.
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.

        Args:
            file_id (int): ID of the file to get the settings for.

        Authentication:
            MAY be required depending on the application settings.

        Returns:
            Instance of the FileSettings schema containing the parsed file settings

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            raise DESFireException("No application selected, call select_application first")

        logger.info(
            f"Executing command: get_file_settings (0x{DESFireCommand.GET_FILE_SETTINGS.value:02x}) for file {file_id}"
        )

        # Get the file settings
        raw_data = raw_data = self._transceive(
            self._command(DESFireCommand.GET_FILE_SETTINGS, file_id),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )
        logger.debug(f"Raw data: {raw_data.hex(' ')}")

        # Parse the raw data
        file_settings = FileSettings()
        file_settings.parse(raw_data)
        logger.debug(f"File settings: {repr(file_settings)}")

        return file_settings

    def read_file_data(self, file_id: int, file_settings: FileSettings) -> bytes:
        """
        Read file data for file_id. SelectApplication needs to be called first
        Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.

        Args:
            file_id (int): ID of the file to get the settings for.
            file_settings (FileSettings): Instance of the FileSettings schema containing the file settings.
                Can be obtained using the `get_file_settings` method.

        Authentication:
            MAY be required depending on the application settings.

        Raises:
            DESFireException: if an invalid configuration is provided

        Returns:
            bytes: Raw data read from the file
        """

        if not self.last_selected_application:
            logger.error("Tried to read file data without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        assert file_settings.encryption is not None
        logger.info(f"Executing command: read_file_data (0x{DESFireCommand.READ_DATA.value:02x}) for file {file_id:x}")

        length = file_settings.file_size
        ioffset = 0
        ret = bytearray()

        while length > 0:
            count = min(length, 48)
            logger.debug(f"Reading {count} bytes from offset {ioffset}")
            ret.extend(
                self._transceive(
                    self._command(
                        DESFireCommand.READ_DATA,
                        file_id,
                        struct.pack("<I", ioffset)[:3],
                        struct.pack("<I", count)[:3],
                    ),
                    DESFireCommunicationMode.PLAIN,
                    file_settings.encryption,
                )
            )
            logger.debug(f"Read raw data: {ret.hex(' ')}")
            ioffset += count
            length -= count

        logger.debug(f"Total data that has been read: {ret.hex(' ')}")
        return bytes(ret)

    def create_standard_file(self, file_id: int, file_settings: FileSettings):
        """
        Creates a standard data file in the application currently selected. `select_application` must be called first.

        Authentication:
            MAY be required depending on the application settings.

        Args:
            file_id (int): ID of the file to get the settings for.
            file_settings (FileSettings): Instance of the FileSettings schema containing the file settings that
                should be applied to the file.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            logger.error("Tried to create file without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        if not 0 <= file_settings.file_size <= 0xFF:
            logger.error("File size must be between 0 and 255 (single byte)")
            raise DESFireException("File size must be between 0 and 255 (single byte)")

        logger.info(
            "Executing command: create_standard_file"
            " (0x{DESFireCommand.CREATE_STD_DATA_FILE.value:02x}) on file {file_id:x}"
        )

        assert file_settings.encryption is not None
        assert file_settings.permissions is not None

        # File size is stored in little endian

        self._transceive(
            self._command(
                DESFireCommand.CREATE_STD_DATA_FILE,
                file_id,
                file_settings.encryption.value,
                file_settings.permissions.get_permissions(),
                struct.pack("<I", file_settings.file_size)[:3],
            ),
            DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
        )

    def write_file_data(self, file_id: int, offset: int, communication_mode: DESFireCommunicationMode, data: bytes):
        """
        Writes data to the file specified by file_id

        Authentication:
            MAY be required depending on the application settings.

        Args:
            file_id (int): ID of the file to get the settings for.
            offset (int): Offset in the file to write the data to.
            communication_mode (DESFireCommunicationMode): Communication mode to use for the data transfer.
                Depends on the file settings that were applied when creating the file.
            data (bytes): Data to write to the file.

        !!! warning
            The data length must not exceed the maximum frame size of 60 bytes.
            It is possible to write longer data, but this is currently not implemented in this library.

        Raises:
            DESFireException: if an invalid configuration is provided
        """
        if not self.last_selected_application:
            logger.error("Tried to write file data without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        logger.info(
            f"Executing command: write_file_data (0x{DESFireCommand.WRITE_DATA.value:02x}) for file {file_id:x}"
        )

        max_length = self.max_frame_size - 1 - 7  # 60 - CMD - CMD Header
        length = len(data)
        if length > max_length:
            logger.error(f"Data length exceeds maximum frame size of {max_length}, not supported yet.")
            raise DESFireException(f"Data length exceeds maximum frame size of {max_length}, not supported yet.")

        self._transceive(
            self._command(
                DESFireCommand.WRITE_DATA,
                file_id,
                struct.pack("<I", offset)[:3],
                struct.pack("<I", length)[:3],
            ),
            communication_mode,
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
            # Command (1 byte) + header file number (1 byte), data length (3 bytes) and offset (3 bytes)
            encryption_offset=8,
        )

    def delete_file(self, file_id: int):
        """
        Deletes the file specified by file_id

        Authentication:
            MAY be required depending on the application settings.

        Args:
            file_id (int): ID of the file to get the settings for.

        Raises:
            DESFireException: if an invalid configuration is provided
        """

        if not self.last_selected_application:
            logger.error("Tried to delete file without selecting an application")
            raise DESFireException("No application selected, call select_application first")

        logger.info(f"Executing command: delete_file (0x{DESFireCommand.DELETE_FILE.value:02x}) for file {file_id:x}")

        self._transceive(
            self._command(DESFireCommand.DELETE_FILE, file_id),
            DESFireCommunicationMode.CMAC if self.is_authenticated else DESFireCommunicationMode.PLAIN,
            DESFireCommunicationMode.PLAIN,
        )
