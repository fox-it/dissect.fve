from uuid import UUID

from dissect.cstruct import cstruct

bde_def = """
/* ======== Volume header information ======== */

typedef struct _FVE_GUID_RECOGNITION {
    CHAR        Guid[16];
    QWORD       InformationOffset[3];
} FVE_GUID_RECOGNITION;

typedef struct _FVE_EOW_GUID_RECOGNITION {
    CHAR        Guid[16];
    QWORD       InformationOffset[3];
    QWORD       EowOffset[2];
} FVE_EOW_GUID_RECOGNITION;

typedef struct _BIOS_PARAMETER_BLOCK {
    USHORT      BytesPerSector;
    UCHAR       SectorsPerCluster;
    USHORT      ReservedSectors;
    UCHAR       Fats;
    USHORT      RootEntries;
    USHORT      Sectors;
    UCHAR       Media;
    USHORT      SectorsPerFat;
    USHORT      SectorsPerTrack;
    USHORT      Heads;
    ULONG       HiddenSectors;
    ULONG       LargeSectors;
} BIOS_PARAMETER_BLOCK;

typedef struct _BOOT_SECTOR {
    CHAR        Jump[3];
    CHAR        Oem[8];
    BIOS_PARAMETER_BLOCK    Bpb;
    CHAR        Unused0[20];
    union {
        ULONG64 InformationLcn;
        ULONG64 Mft2StartLcn;
    };
    CHAR        Unused1[8];
    ULONG64     PartitionLength;
    CHAR        Unused2[28];
    UCHAR       BytesPerSectorShift;
    UCHAR       SectorsPerClusterShift;
    CHAR        Unused3[402];
} BOOT_SECTOR;

/* ======== FVE information and dataset ======== */

enum FVE_STATE {
    DECRYPTED                   = 1,        /* Decrypted state */
    SWITCHING_DIRTY             = 2,        /* In-progress encryption or decryption of large volumes */
                                            /* StateSize will be non-zero, and there will be a conversion log */
    PAUSED                      = 3,        /* Seen on Vista volume with paused encryption/decryption */
    ENCRYPTED                   = 4,        /* The most common state */
    SWITCHING                   = 5,        /* In-progress encryption or decryption of small volumes */
                                            /* Seen when detaching VHD during encryption/decryption of small disks */
};

enum FVE_KEY_TYPE {
    NONE                        = 0x0000,
    EXTERNAL                    = 0x0005,   /* External VMKs have a USE_KEY with this key type */

    STRETCH_KEY                 = 0x1000,
    STRETCH_KEY_1               = 0x1001,
    AES_CCM_256_0               = 0x2000,
    AES_CCM_256_1               = 0x2001,
    EXTERN_KEY                  = 0x2002,
    VMK                         = 0x2003,
    AES_CCM_256_2               = 0x2004,
    HASH_256                    = 0x2005,

    AES_128_DIFFUSER            = 0x8000,
    AES_256_DIFFUSER            = 0x8001,
    AES_128                     = 0x8002,
    AES_256                     = 0x8003,
    AES_XTS_128                 = 0x8004,
    AES_XTS_256                 = 0x8005,
};

flag FVE_KEY_PROTECTOR {
    CLEAR                       = 0x0000,   /* Also known as "obfuscated" */
    TPM                         = 0x0100,
    EXTERNAL                    = 0x0200,   /* Startup key */
    TPM_PIN                     = 0x0400,
    RECOVERY_PASSWORD           = 0x0800,   /* Recovery password */
    PASSPHRASE                  = 0x2000,   /* User passphrase */
};

flag FVE_KEY_FLAG {
    NONE                        = 0x00,
    ENHANCED_PIN                = 0x04,
    ENHANCED_CRYPTO             = 0x10,
    PBKDF2                      = 0x40,
};

enum FVE_DATUM_ROLE : USHORT {
    PROPERTY                    = 0x0000,

    UNKNOWN_1                   = 0x0001,

    VOLUME_MASTER_KEY_INFO      = 0x0002,
    FULL_VOLUME_ENCRYPTION_KEY  = 0x0003,
    VALIDATION                  = 0x0004,

    UNKNOWN_5                   = 0x0005,

    STARTUP_KEY                 = 0x0006,
    DESCRIPTION                 = 0x0007,

    UNKNOWN_8                   = 0x0008,
    UNKNOWN_9                   = 0x0009,
    UNKNOWN_A                   = 0x000A,
    AUTO_UNLOCK                 = 0x000B,
    FULL_VOLUME_ENCRYPTION_KEY_2    = 0x000C,
    UNKNOWN_D                   = 0x000D,
    UNKNOWN_E                   = 0x000E,

    VIRTUALIZATION_INFO         = 0x000F,
    VALIDATION_HASH             = 0x0011,
};

enum FVE_DATUM_TYPE : USHORT {
    ERASED                      = 0x0000,
    KEY                         = 0x0001,
    UNICODE                     = 0x0002,
    STRETCH_KEY                 = 0x0003,
    USE_KEY                     = 0x0004,
    AES_CCM_ENCRYPTED_KEY       = 0x0005,
    TPM_ENCRYPTED_BLOB          = 0x0006,
    VALIDATION_INFO             = 0x0007,
    VOLUME_MASTER_KEY_INFO      = 0x0008,
    EXTERNAL_INFO               = 0x0009,
    UPDATE                      = 0x000A,
    ERROR_LOG                   = 0x000B,
    ASYMMETRIC_ENCRYPTED_KEY    = 0x000C,
    EXPORTED_KEY                = 0x000D,
    PUBLIC_KEY_INFO             = 0x000E,
    VIRTUALIZATION_INFO         = 0x000F,
    SIMPLE_1                    = 0x0010,
    SIMPLE_2                    = 0x0011,
    CONCAT_HASH_KEY             = 0x0012,
    SIMPLE_3                    = 0x0013,
    SIMPLE_LARGE                = 0x0014,
    BACKUP_INFO                 = 0x0015,
};

typedef struct _FVE_INFORMATION {
    CHAR        Signature[8];
    USHORT      HeaderSize;
    USHORT      Version;
    USHORT      CurrentState;
    USHORT      NextState;
    ULONG64     StateOffset;
    ULONG       StateSize;
    ULONG       VirtualizedSectors;
    ULONG64     InformationOffset[3];
    union {
        ULONG64 Mft2StartLcn;
        ULONG64 VirtualizedBlockOffset;
    };
} FVE_INFORMATION;

typedef struct _FVE_DATASET {
    ULONG       Size;
    ULONG       Version;
    ULONG       StartOffset;
    ULONG       EndOffset;
    CHAR        Identification[16];
    ULONG       NonceCounter;
    USHORT      FvekType;
    USHORT      _Unknown;
    ULONG64     CreationTime;
} FVE_DATASET;

typedef struct _FVE_DATUM {
    USHORT      Size;
    USHORT      Role;
    USHORT      Type;
    USHORT      Flags;
} FVE_DATUM;

typedef struct _FVE_VALIDATION {
    USHORT      Size;
    USHORT      Version;
    ULONG       Crc32;
    // FVE_DATUM   IntegrityCheck;
} FVE_VALIDATION;

/* ======== FVE datums ======== */

typedef struct _FVE_DATUM_SIMPLE {
    ULONG       Data;
} FVE_DATUM_SIMPLE;

typedef struct _FVE_DATUM_SIMPLE_LARGE {
    ULONG64     Data;
} FVE_DATUM_SIMPLE_LARGE;

typedef struct _FVE_DATUM_GUID {
    CHAR        Guid[16];
} FVE_DATUM_GUID;

typedef struct _FVE_DATUM_KEY {
    USHORT      KeyType;
    USHORT      KeyFlags;
    // CHAR        Data[];
} FVE_DATUM_KEY;

typedef struct _FVE_DATUM_UNICODE {
    // wchar       Text[];
} FVE_DATUM_UNICODE;

typedef struct _FVE_DATUM_STRETCH_KEY {
    USHORT      KeyType;
    USHORT      KeyFlags;
    CHAR        Salt[16];
} FVE_DATUM_STRETCH_KEY;

typedef struct _FVE_DATUM_USE_KEY {
    USHORT      KeyType;
    USHORT      KeyFlags;
} FVE_DATUM_USE_KEY;

typedef struct _FVE_NONCE {
  ULONG64       DateTime;
  ULONG         Counter;
} FVE_NONCE;

typedef struct _FVE_DATUM_AESCCM_ENC {
    FVE_NONCE   Nonce;
    CHAR        MAC[16];
    // CHAR        Data[];
} FVE_DATUM_AESCCM_ENC;

typedef struct _FVE_DATUM_TPM_ENC_BLOB {
    ULONG       PcrBitmap;
    // CHAR        Data[];
} FVE_DATUM_TPM_ENC_BLOB;

typedef struct _FVE_DATUM_VALIDATION_ENTRY {
    ULONG       _Unknown1;
    ULONG       _Unknown2;
    CHAR        Hash[32];
} FVE_DATUM_VALIDATION_ENTRY;

typedef struct _FVE_DATUM_VALIDATION_INFO {
    // FVE_DATUM_VALIDATION_ENTRY  AllowList[];
} FVE_DATUM_VALIDATION_INFO;

typedef struct _FVE_DATUM_VMK_INFO {
    CHAR        Identifier[16];
    ULONG64     DateTime;
    USHORT      _Unknown1;
    USHORT      Priority;
} FVE_DATUM_VMK_INFO;

typedef struct _FVE_DATUM_EXTERNAL_INFO {
    CHAR        Identifier[16];
    ULONG64     DateTime;
} FVE_DATUM_EXTERNAL_INFO;

typedef struct _FVE_DATUM_UPDATE {
    // Unknown
} FVE_DATUM_UPDATE;

typedef struct _FVE_DATUM_ERROR_LOG {
    // Unknown
} FVE_DATUM_ERROR_LOG;

typedef struct _FVE_DATUM_ASYM_ENC_BLOB {
    // CHAR        Data[];
} FVE_DATUM_ASYM_ENC_BLOB;

typedef struct _FVE_DATUM_EXPORTED_PUBLIC_KEY {
    // CHAR        Data[];
} FVE_DATUM_EXPORTED_PUBLIC_KEY;

typedef struct _FVE_DATUM_PUBLIC_KEY_INFO {
    // CHAR        Data[];
} FVE_DATUM_PUBLIC_KEY_INFO;

typedef struct _FVE_DATUM_VIRTUALIZATION_INFO {
    ULONG64     VirtualizedBlockOffset;
    ULONG64     VirtualizedBlockSize;
} FVE_DATUM_VIRTUALIZATION_INFO;

typedef struct _FVE_DATUM_CONCAT_HASH_KEY {
    // Unknown
} FVE_DATUM_CONCAT_HASH_KEY;

typedef struct _FVE_DATUM_BACKUP_INFO {
    // Unknown
} FVE_DATUM_BACKUP_INFO;

typedef struct _FVE_DATUM_AESCBC256_HMAC_SHA512_ENC {
    CHAR        Iv[16];
    CHAR        Mac[64];
    // CHAR        Data[];
} FVE_DATUM_AESCBC256_HMAC_SHA512_ENC;

/* ======== EOW structures ======== */

typedef struct _FVE_EOW_INFORMATION {
    CHAR        HeaderSignature[8];
    USHORT      HeaderSize;
    USHORT      Size;
    ULONG       SectorSize;
    ULONG       _Unknown1;
    ULONG       ChunkSize;
    ULONG       ConvLogSize;
    ULONG       _Unknown2;
    ULONG       RegionCount;
    ULONG       Crc32;
    ULONG64     EowOffset[2];
    ULONG64     BitmapOffsets[(Size - HeaderSize) / 8];
} FVE_EOW_INFORMATION;

typedef struct _FVE_EOW_BITMAP {
    CHAR        HeaderSignature[10];
    USHORT      HeaderSize;
    ULONG       Size;
    ULONG       _Unknown1;
    ULONG64     RegionOffset;
    ULONG64     RegionSize;
    ULONG64     ConvLogOffset;
    ULONG       RecordOffset[2];
    ULONG       RecordSize;
    ULONG       Crc32;
} FVE_EOW_BITMAP;

typedef struct _FVE_EOW_BITMAP_RECORD {
    CHAR        HeaderSignature[10];
    USHORT      HeaderSize;
    ULONG       Size;
    ULONG       BitmapSize;
    ULONG64     SequenceNumber;
    ULONG       Flags;
    ULONG       Crc32;
    // ULONG       Bitmap[];
} FVE_EOW_BITMAP_RECORD;
"""

c_bde = cstruct().load(bde_def)

FVE_STATE = c_bde.FVE_STATE
FVE_KEY_TYPE = c_bde.FVE_KEY_TYPE
FVE_KEY_FLAG = c_bde.FVE_KEY_FLAG
FVE_KEY_PROTECTOR = c_bde.FVE_KEY_PROTECTOR

FVE_DATUM_ROLE = c_bde.FVE_DATUM_ROLE
FVE_DATUM_TYPE = c_bde.FVE_DATUM_TYPE

# Volume signatures
BITLOCKER_SIGNATURE = b"-FVE-FS-"
BITLOCKER_TO_GO_SIGNATURE = b"MSWIN4.1"

EOW_SIGNATURE = b"FVE-EOW\x00"
EOW_BM_SIGNATURE = b"FVE-EOWBM\x00"
EOW_BR_SIGNATURE = b"FVE-EOWBR\x00"

CONV_MAGIC = b"FVEHDRLO"[::-1]

INFORMATION_OFFSET_GUID = UUID("4967d63b-2e29-4ad8-8399-f6a339e3d001")
EOW_INFORMATION_OFFSET_GUID = UUID("92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8")

CIPHER_MAP = {
    FVE_KEY_TYPE.AES_128_DIFFUSER: "aes-cbc-128-elephant",
    FVE_KEY_TYPE.AES_256_DIFFUSER: "aes-cbc-256-elephant",
    FVE_KEY_TYPE.AES_128: "aes-cbc-128-eboiv",
    FVE_KEY_TYPE.AES_256: "aes-cbc-256-eboiv",
    FVE_KEY_TYPE.AES_XTS_128: "aes-xts-128-plain64",
    FVE_KEY_TYPE.AES_XTS_256: "aes-xts-256-plain64",
}
