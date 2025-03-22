from desfire import diversify_key


def test_diversify_nxp_application_note():
    """
    Tests the diversification of a key based on the NXP application note AN10922.

    Test data coming from section 2.2.1 from https://www.nxp.com/docs/en/application-note/AN10922.pdf
    """

    MK = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    UID = bytes.fromhex("04782E21801D80")
    APPID = bytes.fromhex("3042F5")
    SYSID = bytes.fromhex("4E585020416275")
    EXPECTED_RESULT = bytes.fromhex("A8DD63A3B89D54B37CA802473FDA9175")

    diversify_data = bytes([0x01]) + UID + APPID + SYSID
    key = MK

    div_key = diversify_key(key, diversify_data, pad_to_32=True)

    assert EXPECTED_RESULT == div_key


def test_diversify_no_32_padding():
    """
    Tests the diversification of a key based on the NXP application note AN10922.
    This particular example covers the case where the diversification data is not padded to 32 bytes
    but to the next multiple of 16 bytes, which typically is just 16.
    """

    MK = bytes.fromhex("83A66CF43605111802A2616FA0C5E2FF")
    UID = bytes.fromhex("044D0702195E80")
    APPID = bytes.fromhex("DADADA")
    SYSID = bytes.fromhex("715517")
    EXPECTED_RESULT = bytes.fromhex("DAE9B8D3136B2DAE35D58678F378B0B1")

    diversify_data = bytes([0x01]) + UID + APPID + SYSID
    key = MK

    div_key = diversify_key(key, diversify_data, pad_to_32=False)

    assert EXPECTED_RESULT == div_key
