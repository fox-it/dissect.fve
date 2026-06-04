from __future__ import annotations

from dissect.cstruct import cstruct

# References:
#   - https://veracrypt.jp/en/Encryption%20Scheme.html
#   - https://veracrypt.jp/en/VeraCrypt%20Volume%20Format%20Specification.html
#   - https://github.com/veracrypt/VeraCrypt/blob/master/src/Volume/VolumeHeader.h
veracrypt_def = """
struct VolumeHeader {
    // char     salt[64];
    char        magic[4];           // b"VERA"
    uint16      version;
    uint16      client_version;
    char        crc32[4];           // CRC32 checksum of bytes 256-511
    char        reserved_1[16];     // 16 * 0x00
    uint64      hidden_volume_size;
    uint64      volume_size;
    uint64      mk_scope_offset;    // offset in bytes of master key scope
    uint64      mk_scope_size;
    uint32      flags;              // bit 0 = system_encryption
                                    // bit 1 = non-system in-place encrypted/decrypted volume
                                    // bit 2-31 = reserved
    uint32      sector_size;
    char        reserved_2[120];    // 120 * 0x00
    char        crc32_decrypted[4]; // CRC32 checksum of decrypted bytes 64-251
    char        master_keys[256];   // concatenated primary and secondary master keys
};
"""

c_veracrypt = cstruct(endian=">").load(veracrypt_def)

TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET = (63 - 1) * 512  # 31744
