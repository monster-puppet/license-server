from maya import cmds

HEADER = "NEW CLIENT MAYA TOOLS"
MODULE_NAME = 'NewClientModule'

MAYA_DEFAULT_SCENE_SETTINGS = {'axis': 'y', 'fps': 'ntsc', 'unit': 'cm'}


class Paths(object):
    root = cmds.getModulePath(moduleName=MODULE_NAME)
    presets = fr'{root}/presets'


paths = Paths()


def set_default_timeline():
    cmds.playbackOptions(minTime=0)
    cmds.currentTime(0)


def set_default_up_axis(up_axis='y'):
    if not cmds.upAxis(q=True, axis=True) == up_axis:
        cmds.upAxis(axis=up_axis)


def set_default_fps(fps='ntsc'):
    if not cmds.currentUnit(time=True, q=True) == fps:
        cmds.currentUnit(time=fps)


def set_default_unit(unit='cm'):
    if not cmds.currentUnit(linear=True, q=True) == unit:
        cmds.currentUnit(linear=unit)

