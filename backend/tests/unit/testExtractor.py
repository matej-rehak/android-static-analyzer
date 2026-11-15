import os
from pathlib import Path

import pytest

from apkscan.exceptions import InvalidApkError
from apkscan.extractor import computeFileHashes, loadApk, parseSdkVersion, validateApkFile


def testFileHashesMatchKnownValues(tmp_path: Path):
    file_path = tmp_path / "abc.bin"
    file_path.write_bytes(b"abc")

    hashes = computeFileHashes(file_path)

    assert hashes.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def testMissingFileRaises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        validateApkFile(tmp_path / "chybi.apk")


def testNoZipFileRaises(tmp_path: Path):
    file_path = tmp_path / "text.apk"
    file_path.write_text("tohle není apk")

    with pytest.raises(InvalidApkError):
        validateApkFile(file_path)

def testParseSdkVersionMissing():
    assert parseSdkVersion(None) is None

def testParseSdkVersionNotNumber():
    assert parseSdkVersion("abc") is None

def testLoadApk():
    path = os.environ.get("APKSCAN_APK")
    if path is None:
        pytest.skip("není nastavena cesta k APK")

    loaded = loadApk(Path(path))

    assert loaded.info.package is not None
    assert len(loaded.info.sha256) == 64
    assert all(char in "0123456789abcdef" for char in loaded.info.sha256.lower())
