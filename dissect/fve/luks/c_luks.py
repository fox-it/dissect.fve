from __future__ import annotations

from dissect.cstruct import cstruct

luks_def = """
/* =========== LUKS1 =========== */
#define LUKS_CIPHERNAME_L       32
#define LUKS_CIPHERMODE_L       32
#define LUKS_HASHSPEC_L         32
#define LUKS_DIGESTSIZE         20  // since SHA1
#define LUKS_HMACSIZE           32
#define LUKS_SALTSIZE           32
#define LUKS_NUMKEYS            8

// Minimal number of iterations
#define LUKS_MKD_ITERATIONS_MIN     1000
#define LUKS_SLOT_ITERATIONS_MIN    1000

// Iteration time for digest in ms
#define LUKS_MKD_ITERATIONS_MS  125

#define LUKS_KEY_DISABLED_OLD   0
#define LUKS_KEY_ENABLED_OLD    0xCAFE

#define LUKS_KEY_DISABLED       0x0000DEAD
#define LUKS_KEY_ENABLED        0x00AC71F3

#define LUKS_STRIPES 4000

// partition header starts with magic
#define LUKS_MAGIC_L            6

/* Actually we need only 37, but we don't want struct autoaligning to kick in */
#define UUID_STRING_L           40

/* Offset to keyslot area [in bytes] */
#define LUKS_ALIGN_KEYSLOTS     4096

/* Maximal LUKS header size, for wipe [in bytes] */
#define LUKS_MAX_KEYSLOT_SIZE   0x1000000   /* 16 MB, up to 32768 bits key */

/* Any integer values are stored in network byte order on disk and must be converted */

/* DISSECT: Keyblock structure currently separated out due to a cstruct limitation */
struct luks_keyblock {
    uint32_t    active;

    /* parameters used for password processing */
    uint32_t    passwordIterations;

    char        passwordSalt[LUKS_SALTSIZE];
    /* parameters used for AF store/load */
    uint32_t    keyMaterialOffset;
    uint32_t    stripes;
};

struct luks_phdr {
    char        magic[LUKS_MAGIC_L];
    uint16_t    version;
    char        cipherName[LUKS_CIPHERNAME_L];
    char        cipherMode[LUKS_CIPHERMODE_L];
    char        hashSpec[LUKS_HASHSPEC_L];
    uint32_t    payloadOffset;
    uint32_t    keyBytes;
    char        mkDigest[LUKS_DIGESTSIZE];
    char        mkDigestSalt[LUKS_SALTSIZE];
    uint32_t    mkDigestIterations;
    char        uuid[UUID_STRING_L];

    /* DISSECT: Keyblock structure currently separated out due to a cstruct limitation */
    luks_keyblock keyblock[LUKS_NUMKEYS];

    /* Align it to 512 sector size */
    char        _padding[432];
};

/* =========== LUKS2 =========== */

#define LUKS2_MAGIC_L           6
#define LUKS2_UUID_L            40
#define LUKS2_LABEL_L           48
#define LUKS2_SALT_L            64
#define LUKS2_CHECKSUM_ALG_L    32
#define LUKS2_CHECKSUM_L        64

#define LUKS2_KEYSLOTS_MAX      32
#define LUKS2_TOKENS_MAX        32
#define LUKS2_SEGMENT_MAX       32

/*
 * LUKS2 header on-disk.
 *
 * Binary header is followed by JSON area.
 * JSON area is followed by keyslot area and data area,
 * these are described in JSON metadata.
 *
 * Note: uuid, csum_alg are intentionally on the same offset as LUKS1
 * (checksum alg replaces hash in LUKS1)
 *
 * String (char) should be zero terminated.
 * Padding should be wiped.
 * Checksum is calculated with csum zeroed (+ full JSON area).
 */
struct luks2_hdr_disk {
    char        magic[LUKS2_MAGIC_L];
    uint16_t    version;                            /* Version 2 */
    uint64_t    hdr_size;                           /* in bytes, including JSON area */
    uint64_t    seqid;                              /* increased on every update */
    char        label[LUKS2_LABEL_L];
    char        checksum_alg[LUKS2_CHECKSUM_ALG_L];
    uint8_t     salt[LUKS2_SALT_L];                 /* unique for every header/offset */
    char        uuid[LUKS2_UUID_L];
    char        subsystem[LUKS2_LABEL_L];           /* owner subsystem label */
    uint64_t    hdr_offset;                         /* offset from device start in bytes */
    char        _padding[184];
    uint8_t     csum[LUKS2_CHECKSUM_L];
    char        _padding4096[7*512];
    /* JSON area starts here */
};
"""

c_luks = cstruct(endian=">").load(luks_def)

LUKS_MAGIC = b"LUKS\xba\xbe"
LUKS2_MAGIC_1ST = b"LUKS\xba\xbe"
LUKS2_MAGIC_2ND = b"SKUL\xba\xbe"

SECONDARY_HEADER_OFFSETS = [
    0x00004000,
    0x00008000,
    0x00010000,
    0x00020000,
    0x00040000,
    0x00080000,
    0x00100000,
    0x00200000,
    0x00400000,
]
