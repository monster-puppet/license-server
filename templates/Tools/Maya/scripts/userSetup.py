import sys
import getpass
import os
import maya.cmds as cmds
import maya.utils


def maya_startup():
    # Set Qt binding before importing modules that may use Qt
    _maya_version = int(cmds.about(version=True))
    if _maya_version < 2025:
        os.environ["QT_PREFERRED_BINDING"] = "PySide2"
    else:
        os.environ["QT_PREFERRED_BINDING"] = "PySide6"

    # Import after Qt binding is set and Maya is ready
    import startup
    import settings
    import update_lib

    cmds.scriptJob(event=["SceneOpened", startup.maya_setup], runOnce=True)
    update_lib.run_update()

    additional_paths = [
        os.path.normpath(os.path.join(settings.paths.root, "scripts", "external")),
    ]

    for p in additional_paths:
        os.environ["MAYA_SCRIPT_PATH"] = (
            os.environ.get("MAYA_SCRIPT_PATH", "") + ";" + p
        )
        sys.path.append(p)

    print("================================================")
    print(settings.HEADER)
    print("================================================")
    print(f"Local user: {getpass.getuser()}")
    print("System paths:")

    for path in sys.path:
        print(path)

    print("\n================================================")

    return True


def create_menu():
    # Set Qt binding
    _maya_version = int(cmds.about(version=True))
    if _maya_version < 2025:
        os.environ["QT_PREFERRED_BINDING"] = "PySide2"
    else:
        os.environ["QT_PREFERRED_BINDING"] = "PySide6"

    # Create Monster Puppet menu
    if cmds.menu("MonsterPuppetMenu", exists=True):
        cmds.deleteUI("MonsterPuppetMenu")
    
    gMainWindow = cmds.melGlobals()["$gMainWindow"] if cmds.melGlobals().get("$gMainWindow") else "MayaWindow"
    menu = cmds.menu("MonsterPuppetMenu", label="Monster Puppet", parent=gMainWindow, tearOff=True)
    
    cmds.menuItem(label="Update Library", command=lambda x: maya_startup(), parent=menu)
    cmds.menuItem(divider=True, parent=menu)
    cmds.menuItem(label="About", command=lambda x: cmds.confirmDialog(title="Monster Puppet", message="Monster Puppet Maya Tools", button=["OK"]), parent=menu)


# Defer menu creation until Maya is ready
cmds.evalDeferred(create_menu)
