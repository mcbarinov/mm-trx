from dataclasses import dataclass

import base58
from bip_utils import Bip32PathParser, Bip32Slip10Secp256k1, Bip39SeedGenerator
from Crypto.Hash import keccak
from mnemonic import Mnemonic

WORD_STRENGTH = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}


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


def keccak256(data: bytes) -> bytes:
    """
    Calculate Keccak-256 hash of input bytes.

    Args:
        data: Input bytes.

    Returns:
        32-byte Keccak-256 hash.
    """
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


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
    digest = keccak256(pubkey_body)[-20:]
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
        raise ValueError("derivation_path must contain {i}, for example: m/44'/195'/0'/0/{i}")
    if not Mnemonic("english").check(mnemonic):
        raise ValueError("Mnemonic phrase is invalid.")
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    master = Bip32Slip10Secp256k1.FromSeed(seed)

    result: list[DerivedAccount] = []

    for i in range(limit):
        path = derivation_path.replace("{i}", str(i))
        node = master
        for idx in Bip32PathParser.Parse(path):
            node = node.ChildKey(idx)

        priv_key_hex = node.PrivateKey().Raw().ToHex()
        pub_key_bytes = node.PublicKey().RawUncompressed().ToBytes()
        address = pubkey_to_tron_address(pub_key_bytes)

        result.append(DerivedAccount(index=i, path=path, address=address, private_key=priv_key_hex))

    return result
