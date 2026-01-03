import maya.api.OpenMaya as om
import maya.cmds as cmds
import sys
import os

# Plugin info
def maya_useNewAPI():
    pass

def initializePlugin(plugin):
    """Called when plugin is loaded."""
    # Defer execution to after Maya is fully initialized
    cmds.evalDeferred(_run_user_setup, lowestPriority=True)

def uninitializePlugin(plugin):
    """Called when plugin is unloaded."""
    pass

def _run_user_setup():
    """Run the module's userSetup."""
    try:
        # Find our module's scripts folder
        plugin_path = os.path.dirname(__file__)
        module_root = os.path.dirname(plugin_path)
        scripts_path = os.path.join(module_root, 'scripts')
        
        if scripts_path not in sys.path:
            sys.path.insert(0, scripts_path)
        
        # Import and run userSetup
        import userSetup_module
    except Exception as e:
        om.MGlobal.displayError(f'PBP init error: {e}')
