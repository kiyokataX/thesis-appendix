import pytest

from src.classical.affine import AffineCipher


def test_round_trip():
    cipher = AffineCipher(a=5, b=8)
    plaintext = "AFFINE CIPHER"
    assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext


def test_known_vector():
    # Stinson, Cryptography: Theory and Practice, Example 1.3: key (7, 3), "hot" -> "AXG"
    cipher = AffineCipher(a=7, b=3)
    assert cipher.encrypt("hot") == "AXG"
    assert cipher.decrypt("AXG") == "HOT"


def test_non_letters_preserved():
    cipher = AffineCipher(a=3, b=1)
    assert cipher.encrypt("a, b! 123") == "B, E! 123"


def test_textbook_exercise_ciphertext():
    cipher = AffineCipher(a=7, b=22)
    ciphertext = "falszztysyjzyjkywjrztyjztyynaryjkyswarztyegyyj"
    assert cipher.decrypt(ciphertext) == "FIRSTTHESENTENCEANDTHENTHEEVIDENCESAIDTHEQUEEN"


@pytest.mark.parametrize("a", [2, 13, 26])
def test_key_not_coprime_to_26_rejected(a):
    with pytest.raises(ValueError):
        AffineCipher(a=a, b=0)
