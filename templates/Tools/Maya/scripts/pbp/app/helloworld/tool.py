import maya.cmds as cmds
import webbrowser
from mk.vendor.Qt import QtWidgets, QtCore
import mk.maya.lib.ui.monster_puppet_ui as libUI


class TestUI(libUI.MonsterPuppetBaseWindow):
    def __init__(self, parent=None, title="Test UI"):
        super(TestUI, self).__init__(parent)

        self.setup_ui(title)

        libUI.add_callback(self.__class__, "SelectionChanged", self.print_test)

    def setup_ui(self, title, pos=None):
        super().setup_ui(title, pos)

        self.test_btn = QtWidgets.QPushButton("Select something")
        self.test_btn.clicked.connect(self.print_test)

        self.main_layout.addWidget(self.test_btn)

    def open_documentation_page(self):
        webbrowser.open(
            "https://playbyplaystudios.atlassian.net/wiki/spaces/MBS/pages/884968/Development+Team"
        )

    def closeEvent(self, event):
        super().closeEvent(event)

    def print_test(self, *args, **kwargs):
        sel = cmds.ls(sl=True)
        self.test_btn.setText(sel[0] if sel else "None")
