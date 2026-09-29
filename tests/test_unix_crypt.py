"""Pure-Python crypt(3) verification used to recognise documented default passwords."""

import pytest

from src.common.unix_crypt import crypt_matches

VECTORS = [
    # glibc SHA-crypt specification examples
    ("Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
    ("Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."),
    ("Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
    # generated with glibc crypt(3)
    ("abc", "$1$abcdefgh$Kn5qrjcQzV7oAHBJ23Cu3/"),
    ("admin", "$6$Ab3dEf9h$ojcL1cvX0IaHRu0PeiGsPVFAORKVpsz2Ar8rttbtXPhQKDTKUt1houFPfFFycYDmQT82Bef7B35wxbQXYY.xn/"),
    ("admin", "$1$Xy7wQpLm$HHWqZB39GsLnaQGlnZ0uV."),
    ("default", "$5$rounds=6000$Qw12Er34$IoPl8G84w.e4/aYYQH8TJGwO54LRfIEpiD//33a.984"),
]


@pytest.mark.parametrize("password,stored", VECTORS)
def test_known_vectors(password, stored):
    assert crypt_matches(password, stored)
    assert not crypt_matches(password + "x", stored)


@pytest.mark.parametrize("stored", ["", "plaintext", "$2y$10$abcdefghijklmnopqrstuv", "$6$", '"$6$bad"'])
def test_unsupported_or_malformed(stored):
    assert crypt_matches("admin", stored) is False
