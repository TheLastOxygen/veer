# SPDX-License-Identifier: MIT
"""Names, folders and defaults shared by every command."""
import os
import socket

from . import APP_NAME, __version__

SERVICE_TYPE = '_airdrop._tcp.local'
# Apple devices listen on 8770; any port works, since the SRV record names it.
DEFAULT_PORT = 8771
# The icon a Mac draws for us. A known Apple model, as winawdl and omdrop use:
# whether an unknown model is accepted has not been tried.
DEFAULT_MODEL = 'MacBookPro18,3'
# macOS's own receiver flags (sharingd's defaultSFNodeFlags). See PROTOCOL.md.
DEFAULT_FLAGS = 0x3fb
# The AirDrop token first, in case a peer looks at it, then who we are.
USER_AGENT = f'AirDrop/1.0 {APP_NAME}/{__version__}'
SERVER_VERSION = f'{APP_NAME}/{__version__}'
CERTIFICATE_NAME = APP_NAME
MAX_NAME_CHARS = 63

ENV_HOME = 'VEER_HOME'
ENV_DOWNLOAD_DIR = 'VEER_DOWNLOAD_DIR'


def data_dir():
    """Where Veer keeps its own state: VEER_HOME, else %LOCALAPPDATA%\\Veer."""
    override = os.environ.get(ENV_HOME)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    base = os.environ.get('LOCALAPPDATA')
    if base:
        return os.path.join(base, APP_NAME)
    return os.path.join(os.path.expanduser('~'), '.local', 'share', APP_NAME.lower())


def keys_dir():
    return os.path.join(data_dir(), 'keys')


def default_download_dir():
    """VEER_DOWNLOAD_DIR, else ~/Downloads/Veer."""
    override = os.environ.get(ENV_DOWNLOAD_DIR)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(os.path.expanduser('~'), 'Downloads', APP_NAME)


def default_device_name():
    """The name Macs show for this PC, e.g. "DESKTOP-1234 (Veer)"."""
    host = socket.gethostname().split('.')[0] or 'PC'
    suffix = f' ({APP_NAME})'
    return host[:MAX_NAME_CHARS - len(suffix)] + suffix
