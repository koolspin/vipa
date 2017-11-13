import plistlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from struct import *


class Validate:
    """
    Validate an unpacked .ipa file in various ways

    The following rules are enforced. All are treated as errors, except as noted:
    req-001: The root must contain a sub-directory called 'Payload'
    req-002: Payload must contain a single .app sub-directory
    req-003: The .app root must contain an Info.plist file
    req-004: The application-identifier prefix from the provisioning profile Entitlements section must match one of
            the values in the ApplicationIdentifierPrefix array
    req-005: WARNING: Should warn if the provisioning profile has expired
    req-006: The app id from the Entitlements section must match the app id from Info.plist, taking wildcards into account.
    req-007: Executable files should be in the correct format for iOS devices (armv7, armv7s, arm64, etc)
    """
    # 4 bytes for magic - 0xcafebabe
    # 4 bytes for a count of how many slices are in this file
    HEADER_MAGIC_SIZE = 4
    MACHO_HEADER_MAGIC = 0xfeedface
    MACHO_HEADER_CIGAM = 0xcefaedfe
    MACHO64_HEADER_MAGIC = 0xfeedfacf
    MACHO64_HEADER_CIGAM = 0xcffaedfe
    # Size for the fat_arch struct
    FAT_ARCH_SIZE = 8
    # Identifies this file as a fat binary
    FAT_HEADER_MAGIC = 0xcafebabe

    def __init__(self, dest_path) -> None:
        """
        __init__
        :param dest_path: The path to the unpacked .ipa file (location of the Payload folder)
        """
        super().__init__()
        self._root_path = Path(dest_path)
        self._payload_path = None
        self._app_dir = None
        self._plist_file = None
        self._bundle_id = None
        self._executable_file = None

    @property
    def app_dir(self):
        return self._app_dir

    def validate_structure(self):
        """
        Validates the basic structure of an .ipa file
        :return:
        """
        # req-001
        self._payload_path = self._root_path / 'Payload'
        if not self._payload_path.is_dir():
            raise Exception("Root Payload path not found")
        # req-002
        app_dirs = sorted(self._payload_path.glob('*.app'))
        if len(app_dirs) == 0:
            raise Exception("No .app directories found within Payload")
        if len(app_dirs) > 1:
            raise Exception("Multiple .app directories found within Payload")
        for dir1 in app_dirs:
            if not dir1.is_dir():
                raise Exception("{0} is not a directory".format(dir1))
        # req-003
        self._app_dir = dir1
        print('Found app: {0}'.format(dir1))
        self._plist_file = self._app_dir / 'Info.plist'
        if not self._plist_file.is_file():
            raise Exception("Info.plist file was not found in the app bundle")

    def extract_plist(self):
        """
        Extracts information from the Info.plist file
        :return: Dictionary representation of Info.plist contents
        """
        with self._plist_file.open('rb') as plist_fp:
            p_dict = plistlib.load(plist_fp)
            self._bundle_id = p_dict.get('CFBundleIdentifier')
            self._executable_file = p_dict.get('CFBundleExecutable')
            return p_dict

    def extract_provisioning_plist(self, embedded_prov_plist_path):
        """
        Extracts information from the Info.plist file
        :param  embedded_prov_plist_path: Full path to the plist file which is embedded in the provisioning profile
        :return: Dictionary representation of embedded.mobileprovision contents
        """
        with embedded_prov_plist_path.open('rb') as plist_fp:
            p_dict = plistlib.load(plist_fp)
            return p_dict

    def validate_provisioning_plist(self, plist_dict):
        """
        Validate the embedded provisioning plist which was extracted in a previous step.
        :param plist_dict: Dictionary representation of the embedded.mobileprovision file
        :return: None
        """
        app_id_prefix_array = plist_dict['ApplicationIdentifierPrefix']
        entitlements_dict = plist_dict['Entitlements']
        app_identifier_raw = entitlements_dict.get('application-identifier')
        ix = app_identifier_raw.find('.')
        if ix >= 0:
            app_identifier_prefix = app_identifier_raw[:ix]
            app_id = app_identifier_raw[ix+1:]
        else:
            app_identifier_prefix = app_identifier_raw
            app_id = ''
        get_task_allow = entitlements_dict.get('get-task-allow')
        keychain_groups = entitlements_dict.get('keychain-access-groups')
        # req-004
        if app_identifier_prefix not in app_id_prefix_array:
            raise Exception('The entitlements application-identifier {0} does not match any of the given app id prefixes'.format(app_identifier_prefix))
        # req-005
        exp_date = plist_dict['ExpirationDate']
        now = datetime.now()
        if exp_date < now:
            print('The embedded provisioning profile has expired on {0}'.format(exp_date))
        # req-006
        self._validate_app_id(self._bundle_id, app_id)

    def parse_mach_header(self):
        """
        Parse information in the Mach-O header of an iOS executable.
        :return: None
        """
        # req-007
        print('Checking executable file {0}'.format(self._executable_file))
        path_to_executable = self._app_dir / self._executable_file
        with path_to_executable.open('rb') as macho_fp:
            header_magic = macho_fp.read(Validate.HEADER_MAGIC_SIZE)
            res = unpack('>I', header_magic)
            if res[0] == Validate.FAT_HEADER_MAGIC:
                print('Found a fat binary header')
                fat_count = macho_fp.read(Validate.HEADER_MAGIC_SIZE)
                res = unpack('>I', fat_count)
                print('Fat binary contains {0} architectures'.format(res[0]))
            elif res[0] == Validate.MACHO_HEADER_MAGIC:
                print('Found a mach-o header')
            elif res[0] == Validate.MACHO_HEADER_CIGAM:
                print('Found a mach-o header (endian-flipped)')
            elif res[0] == Validate.MACHO64_HEADER_MAGIC:
                print('Found a mach-o 64 bit header')
            elif res[0] == Validate.MACHO64_HEADER_CIGAM:
                print('Found a mach-o 64 bit header (endian-flipped)')
            else:
                raise Exception('Unknown header bytes: {0:#x}'.format(res[0]))

    def _validate_app_id(self, app_id_from_info_plist, app_id_from_provisioning_file):
        """
        Validate the app ids from the Info.plist and provisioning profile to see if they match, taking wildcards into account.
        Examples:
        com.acme.app1, com.acme.app1  => match
        com.acme.app1, com.acme.app2  => fail
        com.acme.app1, com.acme.*   => match
        com.acme.app1, *            => match

        :param app_id_from_info_plist: Full appid from the Info.plist file, ex: com.acme.app1
        :param app_id_from_provisioning_file: App id (possibly wildcard) from the provisioning profile
        :return: None
        """
        has_wildcard = False
        ix = app_id_from_provisioning_file.find('*')
        if ix >= 0:
            has_wildcard = True
            match_app_id = app_id_from_provisioning_file[:ix]
        else:
            match_app_id = app_id_from_provisioning_file
        if has_wildcard:
            wc_len = len(match_app_id)
            match = (app_id_from_info_plist[:ix] == match_app_id)
        else:
            match = (app_id_from_info_plist == match_app_id)
        if not match:
            raise Exception('Bundle ID does not match app ID from provisioning profile: {0}'.format(app_id_from_provisioning_file))

