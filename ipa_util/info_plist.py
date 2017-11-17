from datetime import datetime


class PlistScanner:
    """
    Extracts useful info from Info.plist
    """
    # TODO: This can be improved.

    def __init__(self, plist_dict) -> None:
        super().__init__()
        self._plist_dict = plist_dict

    def dump_info(self):
        """
        Dump keys that are relevant to us. Used mainly for debugging
        :return: A dictionary containing metadata we're interested in
        """
        val_obj = {}
        self._safe_dict_copy('CFBundleIdentifier', val_obj)
        self._safe_dict_copy('MinimumOSVersion', val_obj)
        self._safe_dict_copy('UISupportedInterfaceOrientations', val_obj)
        self._safe_dict_copy('DTSDKName', val_obj)
        self._safe_dict_copy('UIRequiredDeviceCapabilities', val_obj)
        self._safe_dict_copy('CFBundleVersion', val_obj)
        self._safe_dict_copy('CFBundleShortVersionString', val_obj)
        self._safe_dict_copy('CFBundleDisplayName', val_obj)
        self._safe_dict_copy('CFBundleExecutable', val_obj)
        return val_obj

    def _safe_dict_copy(self, key, val_obj):
        """
        Safely copy from the source dict into a target but only if the given key exists
        :param key: The key to look for in the source dict
        :return: None
        """
        val = self._plist_dict.get(key)
        if val is not None:
            val_obj[key] = val


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
        val_obj = {}
        self._safe_dict_copy('AppIDName', val_obj)
        self._safe_dict_copy('ApplicationIdentifierPrefix', val_obj)
        self._safe_dict_copy('Platform', val_obj)
        self._safe_dict_copy('Name', val_obj)
        self._safe_dict_copy('ProvisionsAllDevices', val_obj)
        self._safe_dict_copy('TeamIdentifier', val_obj)
        self._safe_dict_copy('TeamName', val_obj)
        self._safe_dict_copy('UUID', val_obj)
        #
        dt = self._plist_dict.get('CreationDate')
        if dt is not None:
            val_obj['CreationDate'] = dt.isoformat()
        exp_dt = self._plist_dict.get('ExpirationDate')
        if exp_dt is not None:
            val_obj['ExpirationDate'] = exp_dt.isoformat()
        now = datetime.now()
        val_obj['profile_is_expired'] = (exp_dt < now)
        return val_obj

    def _safe_dict_copy(self, key, val_obj):
        """
        Safely copy from the source dict into a target but only if the given key exists
        :param key: The key to look for in the source dict
        :return: None
        """
        val = self._plist_dict.get(key)
        if val is not None:
            val_obj[key] = val

