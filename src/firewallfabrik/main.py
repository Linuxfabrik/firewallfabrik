import sys
from pathlib import Path

from PySide6.QtCore import QLocale, QTranslator, QLibraryInfo
from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QMainWindow,
    QWidget,
)

from . import __version__


# Maps custom widget class names from the .ui file to their Qt base classes.
# As Python implementations are created, we replace QWidget with the real class.
CUSTOM_WIDGET_MAP = {
    'ObjectEditorDockWidget': QDockWidget,
    'FirewallDialog': QWidget,
    'UserDialog': QWidget,
    'InterfaceDialog': QWidget,
    'RuleSetDialog': QWidget,
    'LibraryDialog': QWidget,
    'IPv4Dialog': QWidget,
    'IPv6Dialog': QWidget,
    'PhysicalAddressDialog': QWidget,
    'AddressRangeDialog': QWidget,
    'ClusterDialog': QWidget,
    'ClusterGroupDialog': QWidget,
    'HostDialog': QWidget,
    'NetworkDialog': QWidget,
    'NetworkDialogIPv6': QWidget,
    'CustomServiceDialog': QWidget,
    'IPServiceDialog': QWidget,
    'ICMPServiceDialog': QWidget,
    'TCPServiceDialog': QWidget,
    'UDPServiceDialog': QWidget,
    'TagServiceDialog': QWidget,
    'GroupObjectDialog': QWidget,
    'TimeDialog': QWidget,
    'RoutingRuleOptionsDialog': QWidget,
    'RuleOptionsDialog': QWidget,
    'NATRuleOptionsDialog': QWidget,
    'DNSNameDialog': QWidget,
    'AddressTableDialog': QWidget,
    'ActionsDialog': QWidget,
    'CommentEditorPanel': QWidget,
    'MetricEditorPanel': QWidget,
    'CompilerOutputPanel': QWidget,
    'BlankDialog': QWidget,
    'AttachedNetworksDialog': QWidget,
    'DynamicGroupDialog': QWidget,
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

        ui_path = Path(__file__).parent / 'libgui' / 'FWBMainWindow_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self.setWindowTitle(f'FirewallFabrik {__version__}')


def main():
    print(f'FirewallFabrik GUI {__version__}')

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
