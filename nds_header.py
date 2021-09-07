import struct

def dump_to_file(fpath, data):
    f = open(fpath, "wb")
    f.write(data)
    f.close()

class NDSHeader:
    def __init__(self, fpath):
        self._f = open(fpath, "rb")
        contents = self._f.read(0x1000)
        seek_idx = 0
        def pop_u64():
            nonlocal seek_idx
            val, = struct.unpack("<Q", contents[seek_idx:seek_idx+8])
            seek_idx += 8
            return val
        def pop_u32():
            nonlocal seek_idx
            val, = struct.unpack("<L", contents[seek_idx:seek_idx+4])
            seek_idx += 4
            return val
        def pop_u16():
            nonlocal seek_idx
            val, = struct.unpack("<H", contents[seek_idx:seek_idx+2])
            seek_idx += 2
            return val
        def pop_u8():
            nonlocal seek_idx
            val, = struct.unpack("<B", contents[seek_idx:seek_idx+1])
            seek_idx += 1
            return val
        def pop_bytes(n):
            nonlocal seek_idx
            val = contents[seek_idx:seek_idx+n]
            seek_idx += n
            return val
        def pop_str(n):
            return pop_bytes(n).decode("utf-8").rstrip('\x00')

        self.game_title = pop_str(12)
        self.game_code = pop_str(4)
        self.maker_code = pop_str(2)
        self.unit_code = pop_u8()
        self.encrypt_seed_sel = pop_u8()
        self.device_capacity = pop_u8()
        self.reserved_14 = pop_bytes(7)
        self.revision = pop_u16()
        self.rom_version = pop_u8()
        self.internal_flags = pop_u8()

        self.arm9_offs = pop_u32()
        self.arm9_entry = pop_u32()
        self.arm9_load = pop_u32()
        self.arm9_size = pop_u32();

        self.arm7_offs = pop_u32()
        self.arm7_entry = pop_u32()
        self.arm7_load = pop_u32()
        self.arm7_size = pop_u32();
        
        self.fnt_offs = pop_u32()
        self.fnt_size = pop_u32()
        self.fat_offs = pop_u32()
        self.fat_size = pop_u32()
        
        self.arm9_overlay_offs = pop_u32()
        self.arm9_overlay_size = pop_u32()
        self.arm7_overlay_offs = pop_u32()
        self.arm7_overlay_size = pop_u32()

        self.normal_card_control = pop_u32()
        self.secure_card_control = pop_u32()
        
        self.icon_banner_offs = pop_u32()
        self.secure_area_crc = pop_u16()
        self.secure_timeout = pop_u16()
        
        self.arm9_autoload = pop_u32()
        self.arm7_autoload = pop_u32()
        
        self.secure_disable = pop_bytes(8)
        self.ntr_rom_size = pop_u32()
        self.header_size = pop_u32()
        self.reserved_88 = pop_bytes(56)
        self.nintendo_logo = pop_bytes(156)
        self.nintendo_logo_crc = pop_u16()
        self.header_crc = pop_u16()
        self.debug_reserved = pop_bytes(32)
        
        # Read out data to bytes
        self.arm9_data = self.read_bytes(self.arm9_offs, self.arm9_size)
        self.arm7_data = self.read_bytes(self.arm7_offs, self.arm7_size)
        self.arm9_overlay_data = self.read_bytes(self.arm9_overlay_offs, self.arm9_overlay_size)
        self.arm7_overlay_data = self.read_bytes(self.arm7_overlay_offs, self.arm7_overlay_size)
        
        if not self.is_dsi():
            return
        
        # DSi-enhanced/DSi headers
        self.mbk1_mbk5_settings = pop_bytes(20)
        self.mbk_arm9 = pop_bytes(12)
        self.mbk_arm7 = pop_bytes(12)
        self.mbk9 = pop_u32()
        self.region_flags = pop_u32()
        self.access_control = pop_u32()
        self.scfg_ext7 = pop_u32()
        self.reserved_1BC = pop_u32()

        self.arm9i_offs = pop_u32()
        self.arm9i_entry_unused = pop_u32()
        self.arm9i_load = pop_u32()
        self.arm9i_size = pop_u32()
        
        self.arm7i_offs = pop_u32()
        self.arm7i_sdmmc = pop_u32()
        self.arm7i_load = pop_u32()
        self.arm7i_size = pop_u32()
        
        self.digest_ntr_offs = pop_u32()
        self.digest_ntr_size = pop_u32()
        self.digest_twl_offs = pop_u32()
        self.digest_twl_size = pop_u32()
        self.digest_sector_hashtable_offs = pop_u32()
        self.digest_sector_hashtable_size = pop_u32()
        self.digest_block_hashtable_offs = pop_u32()
        self.digest_block_hashtable_size = pop_u32()
        self.digest_sector_size = pop_u32()
        self.digest_block_sectorcount = pop_u32()

        self.icon_banner_size = pop_u32()
        self.unk_20C = pop_u32()
        self.total_rom_size = pop_u32()
        self.dsi_flags_1 = pop_u32()
        self.dsi_flags_2 = pop_u32()
        self.dsi_flags_3 = pop_u32()

        self.modcrypt_1_offs = pop_u32()
        self.modcrypt_1_size = pop_u32()
        self.modcrypt_2_offs = pop_u32()
        self.modcrypt_2_size = pop_u32()
        
        self.tid = pop_u64()
        self.public_sav_size = pop_u32()
        self.private_sav_size = pop_u32()
        self.parental_controls = pop_bytes(16)
        
        self.arm9_sha1_hmac = pop_bytes(20)
        self.arm7_sha1_hmac = pop_bytes(20)
        self.digest_master_sha1_hmac = pop_bytes(20)
        self.banner_sha1_hmac = pop_bytes(20)
        self.arm9i_dec_sha1_hmac = pop_bytes(20)
        self.arm7i_dec_sha1_hmac = pop_bytes(20)
        self.reserved_378 = pop_bytes(40)
        self.arm9_unsecure_sha1_hmac = pop_bytes(20)
        self.reserved_3B4 = pop_bytes(2636)
        self.reserved_E00 = pop_bytes(0x180)
        self.rsa_sig = pop_bytes(0x80)
        
        # Read out DSi data to bytes
        self.arm9i_data = self.read_bytes(self.arm9i_offs, self.arm9i_size)
        self.arm7i_data = self.read_bytes(self.arm7i_offs, self.arm7i_size)

    def read_bytes(self, offs, size):
        self._f.seek(offs, 0)
        return self._f.read(size)

    def is_dsi(self):
        return (self.unit_code != 0x00)

    def parse_arm7i_overlay(self):
        self.arm7i_overlay_segs = []
        overlay_segs_tmp = []
        num_segs = 0
        total_size = 0
        while True:
            ent_start = self.arm7i_size - (num_segs*0x8) - 0x8
            ent_end = ent_start+0x8
            addr,size = struct.unpack("<LL", self.arm7i_data[ent_start:ent_end])
            
            total_size += size

            if addr >= 0x04000000:
                break
            
            num_segs += 1
            overlay_segs_tmp = [(addr, size)] + overlay_segs_tmp
            
            if num_segs == 1:
                total_size -= size

        idx = 0
        data_seek = 4
        data_left = self.arm7i_size-4
        real_addr = 0
        for s in overlay_segs_tmp:
            addr, size = s
            

            if real_addr == 0:
                real_addr = addr

            if idx & 1 == 1 or data_left < size:
                dat = None
            else:
                dat = self.arm7i_data[data_seek:data_seek+size]

            self.arm7i_overlay_segs = self.arm7i_overlay_segs + [(real_addr, addr, size, data_seek, dat)]

            if idx & 1 == 1:
                real_addr = 0
                idx += 1
                continue
            idx += 1

            data_seek += size
            data_left -= size
            real_addr += size       
            

    def pretty_print(self):
        print(self.game_title, self.game_code, self.maker_code)
        print("")
        print("ARM9 offs:", hex(self.arm9_offs))
        print("ARM9 entry:", hex(self.arm9_entry))
        print("ARM9 load:", hex(self.arm9_load))
        print("ARM9 size:", hex(self.arm9_size))
        print("")
        print("ARM7 offs:", hex(self.arm7_offs))
        print("ARM7 entry:", hex(self.arm7_entry))
        print("ARM7 load:", hex(self.arm7_load))
        print("ARM7 size:", hex(self.arm7_size))
        print("")
        print("FNT offs:", hex(self.fnt_offs))
        print("FNT size:", hex(self.fnt_size))
        print("FAT offs:", hex(self.fat_offs))
        print("FAT size:", hex(self.fat_size))
        print ("")
        print("ARM9 overlay offs:", hex(self.arm9_overlay_offs))
        print("ARM9 overlay size:", hex(self.arm9_overlay_size))
        print("ARM7 overlay offs:", hex(self.arm7_overlay_offs))
        print("ARM7 overlay size:", hex(self.arm7_overlay_size))
        print("ARM9 autoload:", hex(self.arm9_autoload))
        print("ARM7 autoload:", hex(self.arm7_autoload))

        if not self.is_dsi():
            return

        print("")
        print("ARM9i offs:", hex(self.arm9i_offs))
        print("ARM9i entry:", hex(self.arm9i_entry_unused))
        print("ARM9i load:", hex(self.arm9i_load))
        print("ARM9i size:", hex(self.arm9i_size))
        print("")
        print("ARM7i offs:", hex(self.arm7i_offs))
        print("ARM7i sdmmc:", hex(self.arm7i_sdmmc))
        print("ARM7i load:", hex(self.arm7i_load))
        print("ARM7i size:", hex(self.arm7i_size))
        print("")
        print("Title ID:", hex(self.tid))
    
    def dump(self):
        dump_to_file("arm9.bin", self.arm9_data)
        dump_to_file("arm7.bin", self.arm7_data)
        
        if not self.is_dsi():
            return
        
        dump_to_file("arm9i.bin", self.arm9i_data)
        dump_to_file("arm7i.bin", self.arm7i_data)
        
        
