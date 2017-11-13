import sys
import argparse

from ipa_util.info_plist import PlistScanner, EmbeddedProvisioningPlistScanner
from ipa_util.unpack import Unpack
from ipa_util.validate import Validate


def validate_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Path to the input .ipa file")
    args = parser.parse_args()
    if args.input is None:
        print("You must provide a path to the input .ipa file", file=sys.stderr)
        return False, None
    else:
        return True, args.input


if __name__ == '__main__':
    res = validate_args()
    if res[0]:
        src_path = res[1]
        dest_path = '/home/colin/vipa_temp'
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
        info_p.dump_info()
        app_dir = ipa_val.app_dir
        ret = ipa_unpacker.extract_provisioning_info(app_dir)
        print('Return code from extract prov info: {0}'.format(ret[0]))
        if ret[0] == 0:
            embedded_plist_dict = ipa_val.extract_provisioning_plist(ret[1])
            embedded_pscan = EmbeddedProvisioningPlistScanner(embedded_plist_dict)
            embedded_pscan.dump_info()
            ipa_val.validate_provisioning_plist(embedded_plist_dict)
            ipa_val.parse_mach_header()
        # Finally, clean up our mess
        ipa_unpacker.cleanup_dest()
        exit(0)
    else:
        exit(1)
