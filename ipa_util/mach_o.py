import sys
from struct import *


class MachO:
    """
    Apple mach and universal binary parsing.
    Note this class doesn't do much. For our purposes, we're only interested in the headers
    """
    # 4 bytes for magic - 0xcafebabe
    # 4 bytes for a count of how many slices are in this file
    HEADER_MAGIC_SIZE = 4
    MACHO_HEADER_MAGIC = 0xfeedface
    MACHO_HEADER_CIGAM = 0xcefaedfe
    MACHO64_HEADER_MAGIC = 0xfeedfacf
    MACHO64_HEADER_CIGAM = 0xcffaedfe
    # Identifies this file as a fat binary
    FAT_HEADER_MAGIC = 0xcafebabe
    # Size for the cpu type / subtype fields in the mach header
    MACH_ARCH_SIZE = 8
    # Size for the fat_arch struct
    FAT_ARCH_SIZE = 20
    # struct fat_arch
    # {
    #     cpu_type_t    cputype;
    #     cpu_subtype_t cpusubtype;
    #     uint32_t      offset;
    #     uint32_t      size;
    #     uint32_t      align;
    # };
    ARCH_64BIT_FLAG = 0x01000000
    ARCH_MASK       = 0x00ffffff

    def __init__(self, executable_file, executable_name) -> None:
        """
        __init__
        :param executable_file: Full path to the executable file in mach format
        """
        super().__init__()
        self._executable_file = executable_file
        self._executable_name = executable_name
        # cpu type map
        self._cputype_map = {}
        self._cputype_map[7] = 'x86'
        self._cputype_map[12] = 'arm'
        self._cputype_map[14] = 'sparc'
        self._cputype_map[18] = 'ppc'
        self._arm_subtype_map = {}
        self._arm_subtype_map[0] = ''
        self._arm_subtype_map[5] = 'armv4t'
        self._arm_subtype_map[6] = 'armv6'
        self._arm_subtype_map[7] = 'armv5tej'
        self._arm_subtype_map[8] = 'armxscale'
        self._arm_subtype_map[9] = 'armv7'
        self._arm_subtype_map[10] = 'armv7f'
        self._arm_subtype_map[11] = 'armv7s'
        self._arm_subtype_map[12] = 'armv7k'
        self._arm_subtype_map[14] = 'armv6m'
        self._arm_subtype_map[15] = 'armv7m'
        self._arm_subtype_map[16] = 'armv7em'
        if sys.byteorder == 'big':
            self._sys_is_big_endian = True
        else:
            self._sys_is_big_endian = False

    def get_mach_info(self):
        """
        Extract info from the mach file into a python object.
        :return: A python value object
        """
        value_object = {}
        ftype = 'Unknown'
        binary_slices = []
        with self._executable_file.open('rb') as macho_fp:
            header_magic = macho_fp.read(MachO.HEADER_MAGIC_SIZE)
            res = unpack('>I', header_magic)
            if res[0] == MachO.FAT_HEADER_MAGIC:
                ftype = 'fat_binary'
                fat_count = macho_fp.read(MachO.HEADER_MAGIC_SIZE)
                res = unpack('>I', fat_count)
                for i in range(res[0]):
                    slice = {}
                    arch_struct = macho_fp.read(MachO.FAT_ARCH_SIZE)
                    res_arch = unpack('>iiIII', arch_struct)
                    dec_cpu = self._decode_cpu_types(res_arch[0],res_arch[1])
                    slice['cpu_type'] = dec_cpu[0]
                    slice['cpu_subtype'] = dec_cpu[1]
                    binary_slices.append(slice)
            elif res[0] == MachO.MACHO_HEADER_MAGIC:
                ftype = 'mach_o_binary'
                slice = {}
                arch_struct = macho_fp.read(MachO.MACH_ARCH_SIZE)
                if self._sys_is_big_endian:
                    res_arch = unpack('<ii', arch_struct)
                else:
                    res_arch = unpack('>ii', arch_struct)
                dec_cpu = self._decode_cpu_types(res_arch[0],res_arch[1])
                slice['cpu_type'] = dec_cpu[0]
                slice['cpu_subtype'] = dec_cpu[1]
                binary_slices.append(slice)
            elif res[0] == MachO.MACHO_HEADER_CIGAM:
                ftype = 'mach_o_binary'
                slice = {}
                arch_struct = macho_fp.read(MachO.MACH_ARCH_SIZE)
                if not self._sys_is_big_endian:
                    res_arch = unpack('<ii', arch_struct)
                else:
                    res_arch = unpack('>ii', arch_struct)
                dec_cpu = self._decode_cpu_types(res_arch[0],res_arch[1])
                slice['cpu_type'] = dec_cpu[0]
                slice['cpu_subtype'] = dec_cpu[1]
                binary_slices.append(slice)
            elif res[0] == MachO.MACHO64_HEADER_MAGIC:
                ftype = 'mach_64_binary'
                slice = {}
                arch_struct = macho_fp.read(MachO.MACH_ARCH_SIZE)
                if self._sys_is_big_endian:
                    res_arch = unpack('<ii', arch_struct)
                else:
                    res_arch = unpack('>ii', arch_struct)
                dec_cpu = self._decode_cpu_types(res_arch[0],res_arch[1])
                slice['cpu_type'] = dec_cpu[0]
                slice['cpu_subtype'] = dec_cpu[1]
                binary_slices.append(slice)
            elif res[0] == MachO.MACHO64_HEADER_CIGAM:
                ftype = 'mach_64_binary'
                slice = {}
                arch_struct = macho_fp.read(MachO.MACH_ARCH_SIZE)
                if not self._sys_is_big_endian:
                    res_arch = unpack('<ii', arch_struct)
                else:
                    res_arch = unpack('>ii', arch_struct)
                dec_cpu = self._decode_cpu_types(res_arch[0],res_arch[1])
                slice['cpu_type'] = dec_cpu[0]
                slice['cpu_subtype'] = dec_cpu[1]
                binary_slices.append(slice)
            else:
                raise Exception('Unknown header bytes: {0:#x}'.format(res[0]))
        value_object['binary_name'] = self._executable_name
        value_object['binary_type'] = ftype
        value_object['arch_slices'] = binary_slices
        return value_object

    def _decode_cpu_types(self, cpu_type, cpu_subtype):
        """
        Decode the cpu type and subtype values
        :param cpu_type:
        :param cpu_subtype:
        :return: A tuple consisting of the deocoded cputype, subtype
        """
        cpu_subtyp_name = ''
        cpu_typ_num = cpu_type & MachO.ARCH_MASK
        cpu_typ_name = self._cputype_map.get(cpu_typ_num)
        if cpu_typ_name is None:
            cpu_typ_name = '{0:#x}'.format(cpu_typ_num)
        if cpu_type & MachO.ARCH_64BIT_FLAG:
            cpu_typ_name = cpu_typ_name + '64'
        if cpu_typ_num == 12:
            cpu_subtyp_name = self._arm_subtype_map.get(cpu_subtype)
            if cpu_subtyp_name is None:
                cpu_subtyp_name = '{0:#x}'.format(cpu_subtype)
        return cpu_typ_name, cpu_subtyp_name

