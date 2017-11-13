class PlistScanner:
    """
    Extracts useful info from Info.plist
    """

    def __init__(self, plist_dict) -> None:
        super().__init__()
        self._plist_dict = plist_dict

    def dump_info(self):
        """
        Dump keys that are relevant to us. Used mainly for debugging
        :return:
        """
        print('CFBundleIdentifier: {0}'.format(self._plist_dict['CFBundleIdentifier']))
        print('MinimumOSVersion: {0}'.format(self._plist_dict['MinimumOSVersion']))
        print('UISupportedInterfaceOrientations: {0}'.format(self._plist_dict['UISupportedInterfaceOrientations']))
        print('DTSDKName: {0}'.format(self._plist_dict['DTSDKName']))
        if 'UIRequiredDeviceCapabilities' in self._plist_dict:
            print('UIRequiredDeviceCapabilities: {0}'.format(self._plist_dict['UIRequiredDeviceCapabilities']))
        print('CFBundleVersion: {0}'.format(self._plist_dict['CFBundleVersion']))
        print('CFBundleShortVersionString: {0}'.format(self._plist_dict['CFBundleShortVersionString']))
        print('CFBundleDisplayName: {0}'.format(self._plist_dict['CFBundleDisplayName']))
        print('CFBundleExecutable: {0}'.format(self._plist_dict['CFBundleExecutable']))


class EmbeddedProvisioningPlistScanner:
    """
    Extracts useful info from the embedded provisioning plist
    """
    def __init__(self, plist_dict) -> None:
        super().__init__()
        self._plist_dict = plist_dict

    def dump_info(self):
        """
        Dump keys that are relevant to us. Used mainly for debugging
        :return:
        """
        print('AppIDName: {0}'.format(self._plist_dict['AppIDName']))
        print('ApplicationIdentifierPrefix: {0}'.format(self._plist_dict['ApplicationIdentifierPrefix']))
        print('CreationDate: {0}'.format(self._plist_dict['CreationDate']))
        if 'Platform' in self._plist_dict:
            print('Platform: {0}'.format(self._plist_dict['Platform']))
        print('ExpirationDate: {0}'.format(self._plist_dict['ExpirationDate']))
        print('Name: {0}'.format(self._plist_dict['Name']))
        if 'ProvisionsAllDevices' in self._plist_dict:
            print('ProvisionsAllDevices: {0}'.format(self._plist_dict['ProvisionsAllDevices']))
        print('TeamIdentifier: {0}'.format(self._plist_dict['TeamIdentifier']))
        print('TeamName: {0}'.format(self._plist_dict['TeamName']))
        print('UUID: {0}'.format(self._plist_dict['UUID']))
