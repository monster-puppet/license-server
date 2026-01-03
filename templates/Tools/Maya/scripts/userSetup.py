import sys
import getpass
import os
import sys
import maya.cmds as cmds
import startup
import settings
import update_lib


def maya_startup():
    cmds.scriptJob(event=["SceneOpened", run_maya_startup], runOnce=True)
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


def run_maya_startup():
    startup.maya_setup()


maya_startup()
