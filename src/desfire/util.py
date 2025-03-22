import logging
import struct
import zlib

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.number import bytes_to_long, long_to_bytes

from .enums import DESFireKeyType

logger = logging.getLogger(__name__)


def CRC32(data: bytes) -> bytes:
    """
    Calculates a JAMCRC checksum of the given data.
    """
    logger.debug(f"Calculating CRC32 checksum for data: {data.hex(' ')}")

    return struct.pack("<I", zlib.crc32(data) ^ 0xFFFFFFFF)


def shift_bytes(bs: bytes, xor_lsb: int = 0) -> bytes:
    """
    Shifts the bytes to the left by one bit and xors the least significant bit with the given value.
    """
    num = (bytes_to_long(bs) << 1) ^ xor_lsb
    return long_to_bytes(num, len(bs))[-len(bs) :]


def xor_lists(list1: bytes, list2: bytes) -> bytes:
    """
    Takes two lists and performs a bytewise xor on those lists..
    """
    return bytes([a ^ b for a, b in zip(list1, list2)])


def get_ciphermod(key_type: DESFireKeyType, key: bytes, iv: bytes):
    """
    Returns the cipher module for the given key type.
    """
    logger.debug(f"Creating cipher module for key type {key_type.name}")
    if key_type == DESFireKeyType.DF_KEY_AES:
        assert len(key) == 16
        logger.debug("Creating AES cipher module")
        return AES.new(key, AES.MODE_CBC, iv)
    elif key_type == DESFireKeyType.DF_KEY_3K3DES or (key_type == DESFireKeyType.DF_KEY_2K3DES and len(key) == 16):
        logger.debug("Creating 3DES cipher module")
        return DES3.new(key, DES3.MODE_CBC, iv)
    elif key_type == DESFireKeyType.DF_KEY_2K3DES and len(key) == 8:
        logger.debug("Creating 2DES cipher module")
        return DES.new(key, DES.MODE_CBC, iv)
    else:
        logger.warning("Unknown key type when creating cipher module")
        raise ValueError("Unknown key type")
