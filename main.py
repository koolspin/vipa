import sys
import argparse
import tempfile

from ipa_util.info_plist import PlistScanner, EmbeddedProvisioningPlistScanner
from ipa_util.mach_o import MachO
from ipa_util.unpack import Unpack
from ipa_util.validate import Validate


def validate_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Path to the input .ipa file")
    parser.add_argument("--unpack", help="Path to the folder to unpack the .ipa file. A temporary folder wll be used if not given.")
    args = parser.parse_args()
    if args.input is None:
        print("You must provide a path to the input .ipa file", file=sys.stderr)
        return False, None, None
    else:
        return True, args.input, args.unpack


if __name__ == '__main__':
    res = validate_args()
    if res[0]:
        tempdir_obj = None
        src_path = res[1]
        if res[2] is None:
            tempdir_obj = tempfile.TemporaryDirectory(prefix='vipa_')
            dest_path = tempdir_obj.name
        else:
            dest_path = res[2]
        print('Temporary directory path: {0}'.format(dest_path))
        # top level object
        top_level = {}
        root_obj = {}
        # Unpack the zip file
        ipa_unpacker = Unpack(src_path, dest_path)
        ipa_unpacker.unpack_ipa()
        # Validate the structure and find various paths
        ipa_val = Validate(dest_path)
        ipa_val.validate_structure()
        plist_dict = ipa_val.extract_plist()
        #print('dict: {0}'.format(plist_dict))
        # Extract metadata from Info.plist
        info_p = PlistScanner(plist_dict)
        app_meta = info_p.dump_info()
        root_obj['app_meta'] = app_meta
        #
        app_dir = ipa_val.app_dir
        ret = ipa_unpacker.extract_provisioning_info(app_dir)
        print('Return code from extract prov info: {0}'.format(ret[0]))
        if ret[0] == 0:
            embedded_plist_dict = ipa_val.extract_provisioning_plist(ret[1])
            embedded_pscan = EmbeddedProvisioningPlistScanner(embedded_plist_dict)
            prov_info = embedded_pscan.dump_info()
            root_obj['provisioning_info'] = prov_info
            ipa_val.validate_provisioning_plist(embedded_plist_dict)
            # TODO - validate the binary
            #ipa_val.parse_mach_header()
        # Get info on the binary files
        binary_name = ipa_val.executable_name
        binary_path = ipa_val.executable_path
        macho = MachO(binary_path, binary_name)
        mach_info = macho.get_mach_info()
        root_obj['binary_info'] = mach_info
        # Form the top level object
        top_level['ipa_info'] = root_obj
        print('ipa info: {0}'.format(top_level))
        # Finally, clean up our mess
        ipa_unpacker.cleanup_dest()
        if tempdir_obj is not None:
            tempdir_obj.cleanup()
        exit(0)
    else:
        exit(1)
