import getpass
import time

from maya import cmds, OpenMaya
import settings


def maya_setup():
    """
    maya_setup
    :return:
    """
    start_time = time.time()

    # create make scene validation callback
    OpenMaya.MSceneMessage.addCallback(OpenMaya.MSceneMessage.kAfterOpen, scene_validation)
    OpenMaya.MSceneMessage.addCallback(OpenMaya.MSceneMessage.kAfterNew, set_scene_settings)

    file_path = cmds.file(q=True, sn=True)

    if file_path:
        scene_validation()
    else:
        set_scene_settings()

    print("================================================")
    print(rf"PBP Tools load time: {round(time.time() - start_time, 2)} seconds")
    print(r"User: {0}".format(getpass.getuser()))
    print("================================================")


def scene_validation(*args):
    """
    scene_validation
    :return:
    """
    valid_axis = None
    valid_fps = None
    valid_unit = None

    if cmds.upAxis(q=True, axis=True) == settings.MAYA_DEFAULT_SCENE_SETTINGS['axis']:
        valid_axis = True

    if cmds.currentUnit(time=True, q=True) == settings.MAYA_DEFAULT_SCENE_SETTINGS['fps']:
        valid_fps = True

    if cmds.currentUnit(linear=True, q=True) == settings.MAYA_DEFAULT_SCENE_SETTINGS['unit']:
        valid_unit = True

    if not valid_axis or not valid_fps or not valid_unit:
        result = cmds.confirmDialog(
            title='PBP Scene Validation',
            message='Would you like to update scene settings?',
            button=['OK', 'Cancel'],
            defaultButton='OK',
            cancelButton='Cancel',
            dismissString='Cancel')

        if result == 'OK':
            set_scene_settings()


def set_scene_settings(*args):
    settings.set_default_fps()
    settings.set_default_up_axis()
    settings.set_default_unit()
    settings.set_default_timeline()
