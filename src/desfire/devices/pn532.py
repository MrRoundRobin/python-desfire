import time

from ..exceptions import DESFireException
from .base import Device

# Try importing pyserial
try:
    import serial
except ImportError:
    _has_serial = False
else:
    _has_serial = True

_PREAMBLE = 0x00
_STARTCODE1 = 0x00
_STARTCODE2 = 0xFF
_POSTAMBLE = 0x00
_HOSTTOPN532 = 0xD4
_PN532TOHOST = 0xD5
_MIFARE_ISO14443A = 0x00
_COMMAND_SAMCONFIGURATION = 0x14
_COMMAND_INDATAEXCHANGE = 0x40
_COMMAND_INLISTPASSIVETARGET = 0x4A
_ACK = b"\x00\x00\xff\x00\xff\x00"


class PN532UARTDevice(Device):
    """
    Wrapper around a pyserial based connection to a PN532 device.
    """

    def __init__(self, port: str, **kwargs):
        """
        Initializes a device connected to a PN532 device over UART.

        Args:
            port (str): The port to connect to, e.g. "/dev/ttyS0" or "COM1".

        Keyword Args:
            All keyword arguments are passed to the pyserial.Serial constructor.
        """

        if not _has_serial:
            raise ImportError("pyserial is required for using PN532UARTDevice")

        self._uart = serial.Serial(port, **kwargs)
        self._sam_configuration()
        self._listen_for_passive_target(timeout=1)

    def _sam_configuration(self) -> None:
        """Configure the PN532 to read MiFare cards."""
        self._call_function(_COMMAND_SAMCONFIGURATION, params=[0x01, 0x14, 0x01])

    def _write_data(self, framebytes: bytes) -> None:
        """Write a specified count of bytes to the PN532"""
        self._uart.reset_input_buffer()
        self._uart.write(framebytes)

    def _write_frame(self, data: bytes) -> None:
        """Write a frame to the PN532 with the specified data bytes."""
        assert data is not None and 1 < len(data) < 255, "Data must be 1 to 255 bytes."
        # Build frame to send as:
        # - Preamble (0x00)
        # - Start code  (0x00, 0xFF)
        # - Command length (1 byte)
        # - Command length checksum
        # - Command bytes
        # - Checksum
        # - Postamble (0x00)
        length = len(data)
        checksum = _PREAMBLE + _STARTCODE1 + _STARTCODE2 + sum(data)

        frame = bytearray(
            [
                _PREAMBLE,
                _STARTCODE1,
                _STARTCODE2,
                length & 0xFF,
                (~length + 1) & 0xFF,
            ]
        )

        frame.extend(data)
        frame.append((~checksum) & 0xFF)
        frame.append(_POSTAMBLE)

        # Send frame.
        self._write_data(bytes(frame))

    def _wait_ready(self, timeout: float = 1) -> bool:
        """Wait `timeout` seconds"""
        timestamp = time.monotonic()
        while (time.monotonic() - timestamp) < timeout:
            if self._uart.in_waiting > 0:
                return True  # No Longer Busy
            time.sleep(0.01)  # lets ask again soon!
        # Timed out!
        return False

    def _read_data(self, count: int) -> bytes:
        """Read a specified count of bytes from the PN532."""
        frame = self._uart.read(count)
        if not frame:
            raise DESFireException("No data read from PN532")
        return frame

    def _send_command(self, command: int, params: bytes, timeout: float = 1) -> bool:
        """Send specified command to the PN532 and wait for an acknowledgment.
        Will wait up to timeout seconds for the acknowledgment and return True.
        If no acknowledgment is received, False is returned.
        """

        # Build frame data with command and parameters.
        data = bytes([_HOSTTOPN532, command & 0xFF]) + params

        # Send frame and wait for response.
        try:
            self._write_frame(data)
        except OSError:
            return False
        if not self._wait_ready(timeout):
            return False

        # Verify ACK response and wait to be ready for function response.
        if not _ACK == self._read_data(len(_ACK)):
            raise RuntimeError("Did not receive expected ACK from PN532!")

        return True

    def _read_frame(self, length: int) -> bytes:
        """Read a response frame from the PN532 of at most length bytes in size.
        Returns the data inside the frame if found, otherwise raises an exception
        if there is an error parsing the frame.  Note that less than length bytes
        might be returned!
        """
        # Read frame with expected length of data.
        response = self._read_data(length + 7)

        if len(response) < 2:
            raise RuntimeError("Response frame too short!")

        if response[0] != 0x00:
            raise RuntimeError("Response frame preamble does not contain 0x00!")

        # Swallow all the 0x00 values that preceed 0xFF.
        response = response.lstrip(b"\x00")

        if len(response) < 1 or response[0] != 0xFF:
            raise RuntimeError("Response frame preamble does not contain 0xFF!")

        if len(response) < 2:
            raise RuntimeError("Response has no length byte!")

        # Check length & length checksum match.
        frame_len = response[1]

        if (frame_len + response[2]) & 0xFF != 0:
            raise RuntimeError("Response length checksum did not match length!")

        # Check frame checksum value matches bytes.
        checksum = sum(response[3 : frame_len + 4]) & 0xFF

        if checksum != 0:
            raise RuntimeError("Response checksum did not match expected value: ", checksum)

        # Return frame data.
        return response[3 : frame_len + 3]

    def _process_response(self, command: int, response_length: int = 0, timeout: float = 1) -> bytes | None:
        """Process the response from the PN532 and expect up to response_length
        bytes back in a response.  Note that less than the expected bytes might
        be returned! Will wait up to timeout seconds for a response and return
        a bytearray of response bytes, or None if no response is available
        within the timeout.
        """
        if not self._wait_ready(timeout):
            return None

        # Read response bytes.
        response = self._read_frame(response_length + 2)

        # Check that response is for the called function.
        if not (response[0] == _PN532TOHOST and response[1] == (command + 1)):
            raise RuntimeError("Received unexpected command response!")

        # If command was InDataExchange, check that response is success.
        if command == _COMMAND_INDATAEXCHANGE:
            if not response[2] == 0x00:
                raise RuntimeError("Received PN532 error code in response: ", response[2])
            return response[3:]

        # Return response data.
        return response[2:]

    def _call_function(
        self, command: int, response_length: int = 0, params: bytes = b"", timeout: float = 1
    ) -> bytes | None:
        """
        Send specified command to the PN532 and expect up to response_length
        bytes back in a response.  Note that less than the expected bytes might
        be returned!  Params can optionally specify bytes to send as
        parameters to the function call.  Will wait up to timeout seconds
        for a response and return response bytes, or None if no
        response is available within the timeout.
        """
        if not self._send_command(command, params=params, timeout=timeout):
            return None
        return self._process_response(command, response_length=response_length, timeout=timeout)

    def _listen_for_passive_target(self, card_baud: int = _MIFARE_ISO14443A, timeout: float = 1) -> bool:
        """Send command to PN532 to begin listening for a Mifare card. This
        returns True if the command was received successfully. Note, this does
        not also return the UID of a card! `get_passive_target` must be called
        to read the UID when a card is found. If just looking to see if a card
        is currently present use `read_passive_target` instead.
        """
        # Send passive read command for 1 card.  Expect at most a 7 byte UUID.
        try:
            response = self._send_command(
                _COMMAND_INLISTPASSIVETARGET, params=bytes([0x01, card_baud]), timeout=timeout
            )
        except Exception:
            return False  # _COMMAND_INLISTPASSIVETARGET failed

        return response

    def wait_for_card(self, timeout: float = 1) -> bytes | None:
        """Will wait up to timeout seconds and return None if no card is found,
        otherwise bytes with the UID of the found card is returned.
        `listen_for_passive_target` must have been called first in order to put
        the PN532 into a listening mode.
        It can be useful to use this when using the IRQ pin. Use the IRQ pin to
        detect when a card is present and then call this function to read the
        card's UID. This reduces the amount of time spend checking for a card.
        """
        response = self._process_response(_COMMAND_INLISTPASSIVETARGET, response_length=30, timeout=timeout)
        # If no response is available return None to indicate no card is present.
        if response is None:
            return None
        # Check only 1 card with up to a 7 byte UID is present.
        if response[0] != 0x01:
            raise RuntimeError("More than one card detected!")
        if response[5] > 7:
            raise RuntimeError("Found card with unexpectedly long UID!")
        # Return UID of card.
        return response[6 : 6 + response[5]]

    def transceive(self, bytes: bytes) -> bytes:
        """
        Send in APDU request and wait for the response.

        Args:
            bytes (bytes): Outgoing bytes as list of bytes or byte array

        Returns:
            bytes: bytes from the device.
        """
        params = bytes([0x01]) + bytes
        return self._call_function(_COMMAND_INDATAEXCHANGE, response_length=0xFF, params=params) or []
