import hashlib
from pathlib import Path
from typing import NamedTuple

from apkscan.constants import HASH_CHUNK_SIZE, ZIP_MAGIC
from apkscan.exceptions import InvalidApkError


class FileHashes(NamedTuple):
    md5: str
    sha1: str
    sha256: str


def computeFileHashes(path: Path) -> FileHashes:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(HASH_CHUNK_SIZE)

            if not chunk:
                break

            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )


def validateApkFile(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Soubor {path} neexistuje.")

    with path.open("rb") as file:
        file_header = file.read(len(ZIP_MAGIC))

    if file_header != ZIP_MAGIC:
        raise InvalidApkError(f"Soubor {path} není APK, chybí hlavička ZIP.")
