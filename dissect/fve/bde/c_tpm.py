from __future__ import annotations

from dissect.cstruct import cstruct

# References:
# - https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/switch-pcr-banks-on-tpm-2-0-devices
# - https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/decode-measured-boot-logs-to-track-pcr-changes
# - https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
# - https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
# - https://itm4n.github.io/tpm-based-bitlocker/
tpm_def = """
#define TPM2_SHA1_DIGEST_SIZE   20
#define TPM2_SHA256_DIGEST_SIZE	32
#define TPM2_SHA384_DIGEST_SIZE	48
#define TPM2_SHA512_DIGEST_SIZE	64

enum PCR_BITMAP {
    PCR0_HOST_DRIVER_CODE           = 0,
    PCR1_HOST_DRIVER_DATA           = 1,
    PCR2_UEFI_DRIVER_CODE           = 2,
    PCR3_UEFI_DRIVER_DATA           = 3,
    PCR4_UEFI_BOOT_MANAGER_CODE     = 4,
    PCR5_UEFI_BOOT_MANAGER_DATA     = 5,
    PCR6_HOST_PLATFORM_EVENT        = 6,
    PCR7_SECURE_BOOT_STATE          = 7,
    PCR8_RESERVED                   = 8,
    PCR9_RESERVED                   = 9,
    PCR10_RESERVED                  = 10,
    PCR11_BITLOCKER_ACCESS_CONTROL  = 11,
    PCR12_DATA_EVENT                = 12,
    PCR13_KERNEL_BOOT_DRIVER        = 13,
    PCR14_BOOT_AUTHORITY            = 14,
    PCR15_UNKNOWN                   = 15,
    PCR16_DEBUG                     = 16,
    PCR17_RESERVED                  = 17,
    PCR18_RESERVED                  = 18,
    PCR19_RESERVED                  = 19,
    PCR20_RESERVED                  = 20,
    PCR21_RESERVED                  = 21,
    PCR22_RESERVED                  = 22,
    PCR23_RESERVED                  = 23,
};

typedef struct _FVE_DATUM_TPM_ENC_BLOB {
    ULONG       PcrBitmap;
    USHORT      PublicSize;
    CHAR        Public[PublicSize];
    USHORT      PrivateSize;
    CHAR        Private[PrivateSize];
    USHORT      PcrDigestSize;
    CHAR        PcrDigest[PcrDigestSize];
    BYTE        PcrBitmapSize;
    CHAR        PcrBitmap2[PcrBitmapSize];
} FVE_DATUM_TPM_ENC_BLOB;
"""

c_tpm = cstruct(endian=">").load(tpm_def)
