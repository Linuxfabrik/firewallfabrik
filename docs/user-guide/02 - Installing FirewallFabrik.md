# Installing FirewallFabrik

## Requirements

FirewallFabrik requires **Python 3.14** or later. The GUI additionally requires **PySide6** (Qt6 for Python).

## Installing from PyPI

Make sure to include the `[gui]` extra to pull in PySide6 for the graphical interface.

### Using uv (recommended)

The recommended way to install FirewallFabrik. You can run it without a permanent install:

``` bash
uvx --from 'firewallfabrik[gui]' fwf
```

Or install it as a tool:

``` bash
uv tool install 'firewallfabrik[gui]'
```

### Using pipx

``` bash
pipx install 'firewallfabrik[gui]'
```

### Using pip

``` bash
pip install --user 'firewallfabrik[gui]'
```

On certain Linux distributions that protect the system Python environment, you may need to add the `--break-system-packages` flag.

## Installing a Release Candidate

Release Candidates (RC) are pre-release versions published on PyPI for testing before a stable release. By default, pip, uv, and pipx only install stable releases. To install an RC version, you need to explicitly allow pre-releases.

### Using uv

``` bash
uvx --from 'firewallfabrik[gui]' --prerelease allow fwf
```

Or install it as a tool:

``` bash
uv tool install 'firewallfabrik[gui]' --prerelease allow
```

If you already have a stable version installed via `uv tool`, upgrade to the RC:

``` bash
uv tool upgrade firewallfabrik --prerelease allow
```

### Using pipx

``` bash
pipx install 'firewallfabrik[gui]' --pip-args='--pre'
```

### Using pip

``` bash
pip install --user --pre 'firewallfabrik[gui]'
```

Alternatively, you can install a specific RC version directly by pinning the version:

``` bash
uv tool install 'firewallfabrik[gui]==<version>' --prerelease allow
pip install --user 'firewallfabrik[gui]==<version>'
pipx install 'firewallfabrik[gui]==<version>'
```

### Reverting to a stable release

After testing the RC, you can go back to the latest stable release by re-installing without the pre-release flag:

``` bash
uv tool install 'firewallfabrik[gui]' --force
pipx install 'firewallfabrik[gui]' --force
pip install --user 'firewallfabrik[gui]' --force-reinstall
```

## CLI-Only Installation (No GUI)

If you only need the command-line compilers (`fwf-ipt`, `fwf-nft`) and do not need the graphical interface, you can install without the `[gui]` extra. This avoids pulling in PySide6:

``` bash
pip install firewallfabrik
```

## Installing from Git

For development or to run the latest code from the repository:

``` bash
python3.14 -m venv $HOME/venvs/firewallfabrik
source $HOME/venvs/firewallfabrik/bin/activate
pip install --upgrade pip
pip install --editable '.[gui]'
fwf
```

To also install development dependencies (e.g. pytest), add `--group dev`:

``` bash
pip install --editable '.[gui]' --group dev
```

## Using Native PySide6 on Linux

Some Linux distributions ship a native PySide6 package that integrates better with the desktop theme (e.g. `python3-pyside6` on Fedora). To use it instead of the PyPI version:

1.  Install the distribution's PySide6 package, for example:

    ``` bash
    dnf install python3-pyside6
    ```

2.  Install FirewallFabrik **without** the `[gui]` extra so it does not pull in a separate PySide6 from PyPI:

    ``` bash
    pip install firewallfabrik
    ```

3.  If you are using `pipx`, `uv tool`, or a virtual environment, initialize it with `--system-site-packages` so the native PySide6 is inherited.

## Linux Desktop Integration

To add FirewallFabrik to your application menu and associate its icon:

``` bash
cp assets/ch.linuxfabrik.firewallfabrik.desktop $HOME/.local/share/applications/
mkdir -p $HOME/.local/share/icons/hicolor/scalable/apps/
cp src/firewallfabrik/gui/ui/Icons/firewallfabrik.svg \
    $HOME/.local/share/icons/hicolor/scalable/apps/ch.linuxfabrik.firewallfabrik.svg
update-desktop-database $HOME/.local/share/applications/
gtk-update-icon-cache $HOME/.local/share/icons/hicolor/
```

If `gtk-update-icon-cache` reports *No theme index file*, create `$HOME/.local/share/icons/hicolor/index.theme` with the following content:

``` ini
[Icon Theme]
Name=Hicolor
Comment=Fallback Icon Theme
Directories=scalable/apps

[scalable/apps]
Size=48
Type=Scalable
MinSize=16
MaxSize=512
```

Then re-run:

``` bash
gtk-update-icon-cache $HOME/.local/share/icons/hicolor/
```

To register `.fwf` and `.fwb` as known file types so your file manager (Nautilus, Nemo, Thunar, etc.) shows them with the FirewallFabrik icon and offers "Open with \> FirewallFabrik":

``` bash
mkdir -p $HOME/.local/share/mime/packages/
cp assets/ch.linuxfabrik.firewallfabrik.xml $HOME/.local/share/mime/packages/
update-mime-database $HOME/.local/share/mime/
```

This teaches the system that `.fwf` and `.fwb` are FirewallFabrik files. You may need to log out and back in (or restart the file manager) for the changes to take effect.

If `fwf` is installed inside a virtual environment and is not on your system `PATH`, update the desktop file to use the full path:

``` bash
sed -i "s|Exec=fwf|Exec=$VIRTUAL_ENV/bin/fwf|" \
    $HOME/.local/share/applications/ch.linuxfabrik.firewallfabrik.desktop
```

## Running FirewallFabrik

After installation, launch the GUI with:

``` bash
fwf
```

To open a specific database file on startup:

``` bash
fwf myconfig.fwf
fwf -f myconfig.fwf
```

FirewallFabrik can also open Firewall Builder XML files (`.fwb`) directly.

To check the installed version:

``` bash
fwf --version
```

Both X11 and Wayland display servers are supported.

### Running directly from Source

If you have cloned the Git repository and want to run FirewallFabrik without installing it first (e.g. for development or quick testing), you can launch it directly from the source tree. Activate the virtual environment that has the dependencies installed, then use `PYTHONPATH` to point Python at the source directory:

``` bash
source $HOME/venvs/firewallfabrik/bin/activate
cd /path/to/firewallfabrik
PYTHONPATH=src python -m firewallfabrik.gui.app
```

This bypasses the `fwf` entry point and runs the application module directly. It is useful when you want to test local changes immediately without re-installing the package.

## Available Commands

FirewallFabrik provides the following commands:

`fwf`
The graphical interface (requires the `[gui]` extra).

`fwf-ipt`
Command-line compiler for iptables configurations.

`fwf-nft`
Command-line compiler for nftables configurations.
