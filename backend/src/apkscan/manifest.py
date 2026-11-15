from typing import Any

from apkscan.constants import (
    ANDROID_NAMESPACE,
    COMPONENT_TAGS,
    INTENT_ACTIONS_GROUP,
    PERMISSIONS_GROUP,
    PROVIDER_EXPORT_CHANGE_SDK,
)
from apkscan.models import Component, ComponentType, Features, FlagValue


def readAndroidAttribute(element: Any, name: str) -> str | None:
    attributeName = ANDROID_NAMESPACE + name
    return element.get(attributeName)

def parseBooleanAttribute(
    value: str | None,
    defaultValue: bool | None
) -> bool | None:

    if value is None:
        return defaultValue

    return value.lower() == "true"

def readApplicationFlags(application: Any) -> dict[str, FlagValue]:
    flags: dict[str, FlagValue] = {}

    if application is None:
        return flags

    debuggable = readAndroidAttribute(application, "debuggable")
    allowBackup = readAndroidAttribute(application, "allowBackup")
    usesCleartextTraffic = readAndroidAttribute(
        application,
        "usesCleartextTraffic"
    )

    flags["debuggable"] = parseBooleanAttribute(debuggable, False)
    flags["allowBackup"] = parseBooleanAttribute(allowBackup, True)
    flags["usesCleartextTraffic"] = parseBooleanAttribute(
        usesCleartextTraffic,
        None
    )

    return flags

def resolveComponentName(name: str, packageName: str) -> str:
    if name.startswith("."):
        return packageName + name

    if "." not in name:
        return packageName + "." + name

    return name

def readIntentActions(element: Any) -> list[str]:
    actions: list[str] = []

    intentFilters = element.findall("intent-filter")

    for intentFilter in intentFilters:
        actionElements = intentFilter.findall("action")

        for actionElement in actionElements:
            actionName = readAndroidAttribute(actionElement, "name")

            if actionName is not None:
                actions.append(actionName)

    return actions

def isComponentExported(
    element: Any,
    componentType: ComponentType,
    targetSdk: int | None
) -> bool:

    exportedValue = readAndroidAttribute(element, "exported")

    if exportedValue is not None:
        return exportedValue.lower() == "true"

    if componentType == ComponentType.PROVIDER:
        if targetSdk is None:
            return True

        return targetSdk < PROVIDER_EXPORT_CHANGE_SDK

    intentFilters = element.findall("intent-filter")

    return len(intentFilters) > 0

def createComponent(
    element: Any,
    componentType: ComponentType,
    packageName: str,
    targetSdk: int | None
) -> Component:

    componentName = readAndroidAttribute(element, "name")

    if componentName is None:
        componentName = ""

    resolvedName = resolveComponentName(componentName, packageName)
    exported = isComponentExported(element, componentType, targetSdk)
    intentActions = readIntentActions(element)
    requiredPermission = readAndroidAttribute(element, "permission")

    component = Component(
        type = componentType,
        name = resolvedName,
        exported = exported,
        intentActions = intentActions,
        requiredPermission = requiredPermission
    )

    return component

def readComponents(
    application: Any,
    packageName: str,
    targetSdk: int | None
) -> list[Component]:

    components: list[Component] = []

    if application is None:
        return components

    for tag, componentType in COMPONENT_TAGS.items():
        elements = application.findall(tag)

        for element in elements:
            component = createComponent(
                element,
                componentType,
                packageName,
                targetSdk
            )

            components.append(component)

    return components

def collectIntentActions(components: list[Component]) -> set[str]:
    intentActions: set[str] = set()

    for component in components:
        for action in component.intentActions:
            intentActions.add(action)

    return intentActions

def extractManifestFeatures(apk: Any, targetSdk: int | None) -> Features:
    manifest = apk.get_android_manifest_xml()
    application = manifest.find("application")

    packageName = apk.get_package()

    if packageName is None:
        packageName = ""

    components = readComponents(
        application,
        packageName,
        targetSdk
    )

    permissions: set[str] = set(apk.get_permissions())
    intentActions = collectIntentActions(components)
    flags = readApplicationFlags(application)

    features = Features(
        groups = {
            PERMISSIONS_GROUP: permissions,
            INTENT_ACTIONS_GROUP: intentActions
        },
        components = components,
        flags = flags
    )

    return features
