import hashlib
from pathlib import Path
from typing import Any, NamedTuple

from apkscan.constants import HASH_CHUNK_SIZE, ZIP_MAGIC
from apkscan.exceptions import InvalidApkError
from apkscan.models import ApkInfo


class FileHashes(NamedTuple):
    md5: str
    sha1: str
    sha256: str

class LoadedApk:
    def __init__(self, info: ApkInfo, apk: Any, dexFiles: list[Any], analysis: Any) -> None:
        self.info = info
        self.apk = apk
        self.dexFiles = dexFiles
        self.analysis = analysis

class AndroguardResult:
    def __init__(self, apk: Any, dexFiles: list[Any], analysis: Any) -> None:
        self.apk = apk
        self.dexFiles = dexFiles
        self.analysis = analysis

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
        md5 = md5.hexdigest(),
        sha1 = sha1.hexdigest(),
        sha256 = sha256.hexdigest(),
    )


def validateApkFile(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError("Soubor neexistuje: " + str(path))

    with path.open("rb") as file:
        file_header = file.read(len(ZIP_MAGIC))

    if file_header != ZIP_MAGIC:
        raise InvalidApkError("Soubor není APK, chybí hlavička ZIP: " + str(path))

def parseSdkVersion(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None

def analyzeApkWithAndroguard(path: Path) -> AndroguardResult:
    from androguard.misc import AnalyzeAPK
    from loguru import logger

    logger.remove()
    try:
        apk, dexFiles, analysis = AnalyzeAPK(str(path))
    except Exception as error:
        message = "Androguard nedokázal zpracovat " + str(path) + ": " + str(error)
        raise InvalidApkError(message) from error

    return AndroguardResult(apk, dexFiles, analysis)

def loadApk(path: Path) -> LoadedApk:
    validateApkFile(path)

    result = analyzeApkWithAndroguard(path)
    hashes = computeFileHashes(path)

    info = ApkInfo(
        fileName = path.name,
        sizeBytes = path.stat().st_size,
        md5 = hashes.md5,
        sha1 = hashes.sha1,
        sha256 = hashes.sha256,
        package = result.apk.get_package(),
        appName = result.apk.get_app_name(),
        versionName = result.apk.get_androidversion_name(),
        versionCode = result.apk.get_androidversion_code(),
        minSdk = parseSdkVersion(result.apk.get_min_sdk_version()),
        targetSdk = parseSdkVersion(result.apk.get_target_sdk_version())
    )

    return LoadedApk(
        info = info,
        apk = result.apk,
        dexFiles = result.dexFiles,
        analysis = result.analysis
    )
