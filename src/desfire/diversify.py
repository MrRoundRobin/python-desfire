import logging

from .enums import DESFireKeyType
from .key import DESFireKey
from .schemas import KeySettings

logger = logging.getLogger(__name__)


def diversify_key(key_data: bytes, diversification: bytes, pad_to_32: bool = True) -> bytes:
    """
    Generates a diversified key based on NXP application note AN10922

    The diversification data is not standardized but it is recommended to include data that is unique to the
    card and the application. For example, the UID of the card, the AID of the application, and the system ID.

    Args:
        key_data (bytes): Original key data that will be diversified.
        diversification (bytes): Diversification data. Refer to the application note for a recommendation
        pad_to_32 (bool, optional): The NXP application note calls for the diversification data to be padded to
            32 bytes. Depending on the block size of the underlying cipher, this might not be neccessary and
            there may be existing implementations that do not pad the data.


    Returns:
        bytes: Diversified key data
    """

    logger.debug("Diversifying key using NXP AN10922 method")

    # Pad the diversification data to 32 bytes
    padded: bool = False
    if len(diversification) < 32 and pad_to_32:
        logger.debug("Padding diversification data to 32 bytes")
        diversification += bytes([0x80])
        diversification += bytes(32 - len(diversification))
        padded = True

    logger.debug(f"Diversification data: {diversification.hex(' ')}")

    key = DESFireKey(KeySettings(key_type=DESFireKeyType.DF_KEY_AES), key_data)
    key.generate_cmac()
    key.clear_iv()

    # Calculate the diversified key
    return key.calculate_cmac(diversification, pre_padded=padded)
