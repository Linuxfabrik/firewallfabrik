import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QResource, Qt, QLocale, QTranslator, QLibraryInfo, Slot
from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QMainWindow,
    QMessageBox,
    QWidget,
)

from . import __version__

FILE_FILTERS = 'YAML Files (*.yml *.yaml);;FWB Files (*.fwb);;All Files (*)'


# Maps custom widget class names from the .ui file to their Qt base classes.
# As Python implementations are created, we replace QWidget with the real class.
CUSTOM_WIDGET_MAP = {
    'ActionsDialog': QWidget,
    'AddressRangeDialog': QWidget,
    'AddressTableDialog': QWidget,
    'AttachedNetworksDialog': QWidget,
    'BlankDialog': QWidget,
    'ClusterDialog': QWidget,
    'ClusterGroupDialog': QWidget,
    'CommentEditorPanel': QWidget,
    'CompilerOutputPanel': QWidget,
    'CustomServiceDialog': QWidget,
    'DNSNameDialog': QWidget,
    'DynamicGroupDialog': QWidget,
    'FirewallDialog': QWidget,
    'GroupObjectDialog': QWidget,
    'HostDialog': QWidget,
    'ICMPServiceDialog': QWidget,
    'InterfaceDialog': QWidget,
    'IPServiceDialog': QWidget,
    'IPv4Dialog': QWidget,
    'IPv6Dialog': QWidget,
    'LibraryDialog': QWidget,
    'MetricEditorPanel': QWidget,
    'NATRuleOptionsDialog': QWidget,
    'NetworkDialog': QWidget,
    'NetworkDialogIPv6': QWidget,
    'ObjectEditorDockWidget': QDockWidget,
    'PhysicalAddressDialog': QWidget,
    'RoutingRuleOptionsDialog': QWidget,
    'RuleOptionsDialog': QWidget,
    'RuleSetDialog': QWidget,
    'TagServiceDialog': QWidget,
    'TCPServiceDialog': QWidget,
    'TimeDialog': QWidget,
    'UDPServiceDialog': QWidget,
    'UserDialog': QWidget,
}


class FWFUiLoader(QUiLoader):
    """Custom UI loader that populates an existing QMainWindow instance.

    This mimics the C++ ``Ui::FWBMainWindow_q::setupUi(this)`` pattern.
    When ``QUiLoader`` creates the top-level widget (parent is ``None``),
    we return the *base_instance* we were given so that all child widgets,
    menus, toolbars, and dock widgets are added directly to it.

    Unknown custom widget classes are replaced with their Qt base class so
    the .ui can be loaded before all Python widget classes exist.
    """

    def __init__(self, base_instance):
        super().__init__(base_instance)
        self._base_instance = base_instance

    def createWidget(self, class_name, parent=None, name=''):
        # Top-level widget request → return the existing main window
        if parent is None and self._base_instance is not None:
            return self._base_instance
        if class_name in CUSTOM_WIDGET_MAP:
            widget = CUSTOM_WIDGET_MAP[class_name](parent)
            widget.setObjectName(name)
            return widget
        return super().createWidget(class_name, parent, name)


class FWWindow(QMainWindow):
    """Main application window, equivalent to FWWindow in the C++ codebase."""

    def __init__(self):
        super().__init__()

        libgui_path = Path(__file__).parent / 'libgui'
        self._register_resources(libgui_path)

        ui_path = libgui_path / 'FWBMainWindow_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self._current_file = None

        self.setWindowTitle(f'FirewallFabrik {__version__}')
        self.toolBar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)

    @staticmethod
    def _register_resources(libgui_path):
        """Compile MainRes.qrc to a binary .rcc (if needed) and register it."""
        qrc = libgui_path / 'MainRes.qrc'
        rcc = libgui_path / 'MainRes.rcc'
        if not rcc.exists() or rcc.stat().st_mtime < qrc.stat().st_mtime:
            subprocess.run(
                ['pyside6-rcc', '--binary', str(qrc), '-o', str(rcc)],
                check=True,
            )
        QResource.registerResource(str(rcc))

    def _update_title(self):
        if self._current_file:
            self.setWindowTitle(
                f'{self._current_file.name} - FirewallFabrik {__version__}',
            )
        else:
            self.setWindowTitle(f'FirewallFabrik {__version__}')

    @Slot()
    def fileNew(self):
        # Like C++ ProjectPanel::fileNew() / chooseNewFileName():
        # prompt for a location, enforce .fwb suffix, then create the file.
        fd = QFileDialog(self)
        fd.setFileMode(QFileDialog.FileMode.AnyFile)
        fd.setDefaultSuffix('yml')
        fd.setNameFilter(FILE_FILTERS)
        fd.setWindowTitle(self.tr('Create New File'))
        fd.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        if not fd.exec():
            return

        file_path = Path(fd.selectedFiles()[0]).resolve()
        if file_path.suffix == '':
            file_path = file_path.with_suffix('.yml')

        file_path.touch()
        self._current_file = file_path
        self._update_title()

    @Slot()
    def fileOpen(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            self.tr('Open File'),
            '',
            FILE_FILTERS,
        )
        if not file_name:
            return

        file_path = Path(file_name).resolve()
        if not file_path.is_file():
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr(f"File '{file_path}' does not exist or is not readable"),
            )
            return

        self._current_file = file_path
        self._update_title()

    @Slot()
    def fileSave(self):
        if self._current_file:
            return
        self.fileSaveAs()

    @Slot()
    def fileSaveAs(self):
        fd = QFileDialog(self)
        fd.setFileMode(QFileDialog.FileMode.AnyFile)
        fd.setDefaultSuffix('yml')
        fd.setNameFilter(FILE_FILTERS)
        fd.setWindowTitle(self.tr('Save File As'))
        fd.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        if self._current_file:
            fd.setDirectory(str(self._current_file.parent))
            fd.selectFile(self._current_file.name)
        if not fd.exec():
            return

        file_path = Path(fd.selectedFiles()[0]).resolve()
        if file_path.suffix == '':
            file_path = file_path.with_suffix('.yml')

        self._current_file = file_path
        self._update_title()

    @Slot()
    def fileExit(self):
        self.close()


def main():
    print(f'FirewallFabrik {__version__}')

    app = QApplication(sys.argv)
    app.setOrganizationName('Linuxfabrik')
    app.setApplicationName('FirewallFabrik')

    # Load Qt's own translations for the current locale
    locale = QLocale.system().name()
    qt_translator = QTranslator()
    qt_translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if qt_translator.load(f'qt_{locale}', qt_translations_path):
        app.installTranslator(qt_translator)

    mw = FWWindow()
    mw.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
