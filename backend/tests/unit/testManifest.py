
import xml.etree.ElementTree as ElementTree

from apkscan.constants import INTENT_ACTIONS_GROUP
from apkscan.manifest import extractManifestFeatures
from apkscan.models import Component, ComponentType, Features

PACKAGE_NAME = "com.example.app"

MANIFEST_START = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
    f' package="{PACKAGE_NAME}">'
)

MANIFEST_END = "</manifest>"


class FakeApk:

    def __init__(
        self,
        manifestBody: str,
        permissions: list[str] | None = None
    ) -> None:
        manifestXml = MANIFEST_START + manifestBody + MANIFEST_END

        self.manifest = ElementTree.fromstring(manifestXml)
        self.permissions = permissions if permissions is not None else []

    def get_android_manifest_xml(self) -> ElementTree.Element:
        return self.manifest

    def get_permissions(self) -> list[str]:
        return self.permissions

    def get_package(self) -> str:
        return PACKAGE_NAME


def findComponent(features: Features, nameSuffix: str) -> Component:
    for component in features.components:
        if component.name.endswith(nameSuffix):
            return component

    raise AssertionError("Komponenta " + nameSuffix + " nebyla nalezena.")


def testAllowBackupDefaultsToTrue() -> None:
    apk = FakeApk(
        manifestBody="<application/>"
    )

    features = extractManifestFeatures(apk, 33)

    assert features.flags["allowBackup"] is True
    assert features.flags["usesCleartextTraffic"] is None


def testRelativeComponentNameIsResolved() -> None:
    apk = FakeApk(
        manifestBody="""
            <application>
                <activity android:name=".MainActivity"/>
            </application>
        """
    )

    features = extractManifestFeatures(apk, 33)

    assert features.components[0].name == PACKAGE_NAME + ".MainActivity"


def testExplicitExportedFalse() -> None:
    apk = FakeApk(
        manifestBody="""
            <application>
                <receiver
                    android:name=".SmsReceiver"
                    android:exported="false">
                    <intent-filter>
                        <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
                    </intent-filter>
                </receiver>
            </application>
        """
    )

    features = extractManifestFeatures(apk, 33)

    receiver = findComponent(features, ".SmsReceiver")

    assert receiver.exported is False


def testImplicitExportWithIntentFilter() -> None:
    apk = FakeApk(
        manifestBody="""
            <application>
                <receiver android:name=".BootReceiver">
                    <intent-filter>
                        <action android:name="android.intent.action.BOOT_COMPLETED"/>
                    </intent-filter>
                </receiver>
            </application>
        """
    )

    features = extractManifestFeatures(apk, 28)

    receiver = findComponent(features, ".BootReceiver")

    assert receiver.type == ComponentType.RECEIVER
    assert receiver.exported is True
    assert "android.intent.action.BOOT_COMPLETED" in features.groups[INTENT_ACTIONS_GROUP]


def testNoIntentFilterIsNotExported() -> None:
    apk = FakeApk(
        manifestBody="""
            <application>
                <service android:name=".SyncService"/>
            </application>
        """
    )

    features = extractManifestFeatures(apk, 33)

    service = findComponent(features, ".SyncService")

    assert service.exported is False


def testProviderExportDependsOnTargetSdk() -> None:
    apk = FakeApk(
        manifestBody="""
            <application>
                <provider android:name=".DataProvider"/>
            </application>
        """
    )

    oldApp = extractManifestFeatures(apk, 16)
    newApp = extractManifestFeatures(apk, 30)

    oldProvider = findComponent(oldApp, ".DataProvider")
    newProvider = findComponent(newApp, ".DataProvider")

    assert oldProvider.exported is True
    assert newProvider.exported is False


def testManifestWithoutApplication() -> None:
    apk = FakeApk(
        manifestBody=""
    )

    features = extractManifestFeatures(apk, 33)

    assert features.components == []
    assert features.flags == {}
