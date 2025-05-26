from dataclasses import dataclass

import base58
import eth_utils
from eth_account import Account
from eth_account.signers.local import LocalAccount
from mnemonic import Mnemonic

WORD_STRENGTH = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}

Account.enable_unaudited_hdwallet_features()


def generate_mnemonic(num_words: int = 24) -> str:
    """
    Generate a new BIP39 mnemonic phrase.

    Args:
        num_words: Number of words in mnemonic (12, 15, 18, 21, or 24).

    Returns:
        A BIP39 mnemonic phrase string.

    Raises:
        ValueError: If num_words is not a valid BIP39 option.
    """
    if num_words not in WORD_STRENGTH:
        raise ValueError(f"num_words must be one of {list(WORD_STRENGTH.keys())}")
    mnemonic = Mnemonic("english")
    return mnemonic.generate(strength=WORD_STRENGTH[num_words])


@dataclass
class DerivedAccount:
    """
    Represents a derived Tron account.
    """

    index: int
    path: str
    address: str
    private_key: str


def pubkey_to_tron_address(pubkey_bytes: bytes) -> str:
    """
    Convert an uncompressed ECDSA secp256k1 public key to a Tron base58check address.

    Args:
        pubkey_bytes: 65 bytes uncompressed SEC1 public key (starts with 0x04).

    Returns:
        Tron address (Base58Check string, starts with T).

    Raises:
        ValueError: If pubkey_bytes is not in uncompressed format.
    """
    if len(pubkey_bytes) != 65 or pubkey_bytes[0] != 0x04:
        raise ValueError("pubkey_bytes must be uncompressed SEC1 public key (65 bytes, starts with 0x04)")
    pubkey_body = pubkey_bytes[1:]  # Remove 0x04 prefix.
    digest = eth_utils.keccak(pubkey_body)[-20:]
    tron_address_bytes = b"\x41" + digest
    return base58.b58encode_check(tron_address_bytes).decode()


def derive_accounts(
    mnemonic: str, passphrase: str, derivation_path: str = "m/44'/195'/0'/0/{i}", limit: int = 10
) -> list[DerivedAccount]:
    """
    Derive multiple Tron accounts from a BIP39 mnemonic.

    Args:
        mnemonic: BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words).
        passphrase: Optional BIP39 passphrase ("" by default).
        derivation_path: BIP44 path pattern (must contain "{i}" for index).
        limit: Number of accounts to derive.

    Returns:
        List of DerivedAccount objects.

    Raises:
        ValueError: If derivation_path does not contain "{i}".
        ValueError: If mnemonic is not valid.
    """
    if "{i}" not in derivation_path:
        raise ValueError("derivation_path must contain {i}, e.g. m/44'/195'/0'/0/{i}")
    if not Mnemonic("english").check(mnemonic):
        raise ValueError("Mnemonic is invalid")
    result: list[DerivedAccount] = []
    for i in range(limit):
        path = derivation_path.replace("{i}", str(i))
        acc: LocalAccount = Account.from_mnemonic(mnemonic, passphrase=passphrase, account_path=path)
        pubkey_bytes = b"\x04" + acc._key_obj.public_key.to_bytes()  # noqa: SLF001
        priv_key_hex = acc.key.hex()
        address = pubkey_to_tron_address(pubkey_bytes)
        result.append(DerivedAccount(index=i, path=path, address=address, private_key=priv_key_hex))
    return result
