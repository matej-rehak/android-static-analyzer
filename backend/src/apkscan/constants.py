from apkscan.models import ComponentType

HASH_CHUNK_SIZE = 65536

# ZIP začíná těmito čtyřmi bajty
ZIP_MAGIC = b"PK\x03\x04"

ANDROID_NAMESPACE = "{http://schemas.android.com/apk/res/android}"

PERMISSIONS_GROUP = "permissions"
INTENT_ACTIONS_GROUP = "intentActions"

COMPONENT_TAGS = {
    "activity": ComponentType.ACTIVITY,
    "activity-alias": ComponentType.ACTIVITY,
    "service": ComponentType.SERVICE,
    "receiver": ComponentType.RECEIVER,
    "provider": ComponentType.PROVIDER,
}

PROVIDER_EXPORT_CHANGE_SDK = 17
