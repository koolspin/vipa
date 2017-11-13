from zipfile import ZipFile
from pathlib import Path
import subprocess


class Unpack:
    """
    Unpack an ipa file to a specific directory for further processing
    """

    def __init__(self, src_path, dest_path) -> None:
        """
        __init__
        :param src_path: Full path to the source .ipa file
        :param dest_path: Path to a destination folder where the unpacking will be done
        """
        super().__init__()
        self._src_path = src_path
        self._dest_path = dest_path

    def unpack_ipa(self):
        """
        Unpacks the ipa and returns the path where the unpacked file may be found
        :return: Path to the destination folder
        """
        with ZipFile(self._src_path) as ipa_zip:
            ipa_zip.extractall(self._dest_path)
        return self._dest_path

    def cleanup_dest(self):
        """
        Clean up the destination folder by deleting everything in it
        :return: None
        """
        pass

    def extract_provisioning_info(self, app_root):
        """
        Extract information from the embedded.mobileprovision file, which is really a pkcs#7 file in der format.
        There are other ways to do this, but I think this is the cleanest with the only external dependency being openssl in your path.

        Thanks to SO user olivierypg
        https://stackoverflow.com/a/14379814/953365

        Also, Jay Graves:
        https://possiblemobile.com/2013/04/what-is-a-provisioning-profile-part-1/

        :param app_root: Path to the application root folder
        :return: None
        """
        mobile_prov_path = app_root / 'embedded.mobileprovision'
        temp_path = Path(self._dest_path) / 'temp'
        if not temp_path.is_dir():
            temp_path.mkdir()
        temp_plist_path = temp_path / 'embedded_prov.plist'

        openssl_args = []
        openssl_args.append('openssl')
        openssl_args.append('smime')
        openssl_args.append('-inform')
        openssl_args.append('der')
        openssl_args.append('-verify')
        openssl_args.append('-noverify')
        openssl_args.append('-in')
        openssl_args.append(str(mobile_prov_path))
        openssl_args.append('-out')
        openssl_args.append(str(temp_plist_path))
        ret = subprocess.check_call(openssl_args)
        return ret, temp_plist_path

