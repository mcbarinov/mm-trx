import pytest

from mm_trx.account import derive_accounts, generate_mnemonic, pubkey_to_tron_address


def test_generate_mnemonic_length():
    for n in [12, 15, 18, 21, 24]:
        m = generate_mnemonic(n)
        assert len(m.split()) == n


def test_generate_mnemonic_invalid():
    with pytest.raises(ValueError):
        generate_mnemonic(13)


def test_pubkey_to_tron_address_invalid():
    with pytest.raises(ValueError):
        pubkey_to_tron_address(b"\x02" + b"\x00" * 32)  # compressed pubkey (33 bytes)


def test_derive_accounts_invalid_mnemonic():
    with pytest.raises(ValueError):
        derive_accounts("not a valid mnemonic", "")


def test_derive_accounts_known_address(mnemonic, address_0, private_0):
    accounts = derive_accounts(mnemonic, "", derivation_path="m/44'/195'/0'/0/{i}", limit=1)
    assert accounts[0].address == address_0
    assert accounts[0].private_key == private_0
    assert accounts[0].index == 0
    assert accounts[0].path == "m/44'/195'/0'/0/0"
    assert len(accounts[0].private_key) == 64  # hex string


def test_derive_accounts_many():
    mnemonic = generate_mnemonic(12)
    accs = derive_accounts(mnemonic, "", limit=5)
    addresses = {a.address for a in accs}
    assert len(accs) == 5
    assert len(addresses) == 5
