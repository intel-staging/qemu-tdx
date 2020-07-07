/*
 * Copyright (C) 2020 Intel Corporation
 *
 * Author: Isaku Yamahata <isaku.yamahata at gmail.com>
 *                        <isaku.yamahata at intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef HW_I386_UEFI_H
#define HW_I386_UEFI_H

/***************************************************************************/
/*
 * basic EFI definitions
 * supplemented with UEFI Specification Version 2.8 (Errata A)
 * released February 2020
 */
/* UEFI integer is little endian */

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} EFI_GUID;

typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint32_t EFI_BOOT_MODE;

typedef enum {
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiPersistentMemory,
    EfiMaxMemoryType
} EFI_MEMORY_TYPE;


/*
 * data structure firmware volume/file
 * based on
 * UEFI Platform Initialization Specification Version 1.7. vol 3, 3.2.1
 */

#define SIGNATURE_16(A, B)        (((A) | (B << 8)))
#define SIGNATURE_32(A, B, C, D)  (((A) | (B << 8) | (C << 16) | (D << 24)))
#define SIGNATURE_64(A, B, C, D, E, F, G, H)                            \
    (SIGNATURE_32(A, B, C, D) | ((uint64_t)(SIGNATURE_32(E, F, G, H)) << 32))

/***************************************************************************/
/* Firmware Volume format */

typedef uint32_t EFI_FV_FILE_ATTRIBUTES;


#define EFI_FV_FILE_ATTRIB_ALIGNMENT     0x0000001F
#define EFI_FV_FILE_ATTRIB_FIXED         0x00000100
#define EFI_FV_FILE_ATTRIB_MEMORY_MAPPED 0x00000200

typedef uint32_t EFI_FVB_ATTRIBUTES_2;


#define EFI_FVB2_READ_DISABLED_CAP  0x00000001
#define EFI_FVB2_READ_ENABLED_CAP   0x00000002
#define EFI_FVB2_READ_STATUS        0x00000004
#define EFI_FVB2_WRITE_DISABLED_CAP 0x00000008
#define EFI_FVB2_WRITE_ENABLED_CAP  0x00000010
#define EFI_FVB2_WRITE_STATUS       0x00000020
#define EFI_FVB2_LOCK_CAP           0x00000040
#define EFI_FVB2_LOCK_STATUS        0x00000080
#define EFI_FVB2_STICKY_WRITE       0x00000200
#define EFI_FVB2_MEMORY_MAPPED      0x00000400
#define EFI_FVB2_ERASE_POLARITY     0x00000800
#define EFI_FVB2_READ_LOCK_CAP      0x00001000
#define EFI_FVB2_READ_LOCK_STATUS   0x00002000
#define EFI_FVB2_WRITE_LOCK_CAP     0x00004000
#define EFI_FVB2_WRITE_LOCK_STATUS  0x00008000
#define EFI_FVB2_ALIGNMENT          0x001F0000
#define EFI_FVB2_WEAK_ALIGNMENT     0x80000000
#define EFI_FVB2_ALIGNMENT_1        0x00000000
#define EFI_FVB2_ALIGNMENT_2        0x00010000
#define EFI_FVB2_ALIGNMENT_4        0x00020000
#define EFI_FVB2_ALIGNMENT_8        0x00030000
#define EFI_FVB2_ALIGNMENT_16       0x00040000
#define EFI_FVB2_ALIGNMENT_32       0x00050000
#define EFI_FVB2_ALIGNMENT_64       0x00060000
#define EFI_FVB2_ALIGNMENT_128      0x00070000
#define EFI_FVB2_ALIGNMENT_256      0x00080000
#define EFI_FVB2_ALIGNMENT_512      0x00090000
#define EFI_FVB2_ALIGNMENT_1K       0x000A0000
#define EFI_FVB2_ALIGNMENT_2K       0x000B0000
#define EFI_FVB2_ALIGNMENT_4K       0x000C0000
#define EFI_FVB2_ALIGNMENT_8K       0x000D0000
#define EFI_FVB2_ALIGNMENT_16K      0x000E0000
#define EFI_FVB2_ALIGNMENT_32K      0x000F0000
#define EFI_FVB2_ALIGNMENT_64K      0x00100000
#define EFI_FVB2_ALIGNMENT_128K     0x00110000
#define EFI_FVB2_ALIGNMENT_256K     0x00120000
#define EFI_FVB2_ALIGNMENT_512K     0x00130000
#define EFI_FVB2_ALIGNMENT_1M       0x00140000
#define EFI_FVB2_ALIGNMENT_2M       0x00150000
#define EFI_FVB2_ALIGNMENT_4M       0x00160000
#define EFI_FVB2_ALIGNMENT_8M       0x00170000
#define EFI_FVB2_ALIGNMENT_16M      0x00180000
#define EFI_FVB2_ALIGNMENT_32M      0x00190000
#define EFI_FVB2_ALIGNMENT_64M      0x001A0000
#define EFI_FVB2_ALIGNMENT_128M     0x001B0000
#define EFI_FVB2_ALIGNMENT_256M     0x001C0000
#define EFI_FVB2_ALIGNMENT_512M     0x001D0000
#define EFI_FVB2_ALIGNMENT_1G       0x001E0000
#define EFI_FVB2_ALIGNMENT_2G       0x001F0000

typedef struct {
    uint32_t NumBlocks;
    uint32_t Length;
} EFI_FV_BLOCK_MAP_ENTRY;

typedef struct {
    uint8_t ZeroVector[16];
    EFI_GUID FileSystemGuid;
    uint64_t FvLength;
    uint32_t Signature;
    EFI_FVB_ATTRIBUTES_2 Attributes;
    uint16_t HeaderLength;
    uint16_t Checksum;
    uint16_t ExtHeaderOffset;
    uint8_t Reserved[1];
    uint8_t Revision;
    EFI_FV_BLOCK_MAP_ENTRY BlockMap[1];
} EFI_FIRMWARE_VOLUME_HEADER;

#define EFI_FVH_SIGNATURE SIGNATURE_32('_', 'F', 'V', 'H')

#define EFI_FVH_REVISION 0x02

typedef struct {
    EFI_GUID FvName;
    uint32_t ExtHeaderSize;
} EFI_FIRMWARE_VOLUME_EXT_HEADER;

typedef struct {
    uint16_t ExtEntrySize;
    uint16_t ExtEntryType;
} EFI_FIRMWARE_VOLUME_EXT_ENTRY;

#define EFI_FV_EXT_TYPE_OEM_TYPE 0x01
typedef struct {
    EFI_FIRMWARE_VOLUME_EXT_ENTRY Hdr;
    uint32_t TypeMask;

    EFI_GUID Types[];
} EFI_FIRMWARE_VOLUME_EXT_ENTRY_OEM_TYPE;

#define EFI_FV_EXT_TYPE_GUID_TYPE 0x0002
typedef struct {
    EFI_FIRMWARE_VOLUME_EXT_ENTRY Hdr;
    EFI_GUID FormatType;

    uint8_t Data[];
} EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE;

#define EFI_FV_EXT_TYPE_USED_SIZE_TYPE 0x03
typedef struct {
  EFI_FIRMWARE_VOLUME_EXT_ENTRY Hdr;
  uint32_t UsedSize;
} EFI_FIRMWARE_VOLUME_EXT_ENTRY_USED_SIZE_TYPE;

/***************************************************************************/
/* Firmware File */

#pragma pack(push, 1)

typedef union {
    struct {
        uint8_t Header;
        uint8_t File;
    } Checksum;
    uint16_t Checksum16;
} EFI_FFS_INTEGRITY_CHECK;

typedef uint8_t EFI_FV_FILETYPE;
typedef uint8_t EFI_FFS_FILE_ATTRIBUTES;
typedef uint8_t EFI_FFS_FILE_STATE;


#define EFI_FV_FILETYPE_ALL                   0x00
#define EFI_FV_FILETYPE_RAW                   0x01
#define EFI_FV_FILETYPE_FREEFORM              0x02
#define EFI_FV_FILETYPE_SECURITY_CORE         0x03
#define EFI_FV_FILETYPE_PEI_CORE              0x04
#define EFI_FV_FILETYPE_DXE_CORE              0x05
#define EFI_FV_FILETYPE_PEIM                  0x06
#define EFI_FV_FILETYPE_DRIVER                0x07
#define EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER  0x08
#define EFI_FV_FILETYPE_APPLICATION           0x09
#define EFI_FV_FILETYPE_SMM                   0x0A
#define EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE 0x0B
#define EFI_FV_FILETYPE_COMBINED_SMM_DXE      0x0C
#define EFI_FV_FILETYPE_SMM_CORE              0x0D
#define EFI_FV_FILETYPE_MM_STANDALONE         0x0E
#define EFI_FV_FILETYPE_MM_CORE_STANDALONE    0x0F
#define EFI_FV_FILETYPE_OEM_MIN               0xc0
#define EFI_FV_FILETYPE_OEM_MAX               0xdf
#define EFI_FV_FILETYPE_DEBUG_MIN             0xe0
#define EFI_FV_FILETYPE_DEBUG_MAX             0xef
#define EFI_FV_FILETYPE_FFS_MIN               0xf0
#define EFI_FV_FILETYPE_FFS_MAX               0xff
#define EFI_FV_FILETYPE_FFS_PAD               0xf0


#define FFS_ATTRIB_LARGE_FILE         0x01
#define FFS_ATTRIB_DATA_ALIGNMENT2    0x02
#define FFS_ATTRIB_FIXED              0x04
#define FFS_ATTRIB_DATA_ALIGNMENT     0x38
#define FFS_ATTRIB_CHECKSUM           0x40


#define EFI_FILE_HEADER_CONSTRUCTION  0x01
#define EFI_FILE_HEADER_VALID         0x02
#define EFI_FILE_DATA_VALID           0x04
#define EFI_FILE_MARKED_FOR_UPDATE    0x08
#define EFI_FILE_DELETED              0x10
#define EFI_FILE_HEADER_INVALID       0x20


#define EFI_FILE_ALL_STATE_BITS                 \
    (EFI_FILE_HEADER_CONSTRUCTION |             \
     EFI_FILE_HEADER_VALID |                    \
     EFI_FILE_DATA_VALID |                      \
     EFI_FILE_MARKED_FOR_UPDATE |               \
     EFI_FILE_DELETED |                         \
     EFI_FILE_HEADER_INVALID)


typedef struct {
    EFI_GUID Name;
    EFI_FFS_INTEGRITY_CHECK IntegrityCheck;
    EFI_FV_FILETYPE Type;
    EFI_FFS_FILE_ATTRIBUTES Attributes;
    uint8_t Size[3];
    EFI_FFS_FILE_STATE State;
} EFI_FFS_FILE_HEADER;


typedef struct {
    EFI_GUID Name;
    EFI_FFS_INTEGRITY_CHECK IntegrityCheck;
    EFI_FV_FILETYPE Type;
    EFI_FFS_FILE_ATTRIBUTES Attributes;
    uint8_t Size[3];
    EFI_FFS_FILE_STATE State;
    uint64_t ExtendedSize;
} EFI_FFS_FILE_HEADER2;

#define MAX_FFS_SIZE 0x1000000

#pragma pack(pop)


/***************************************************************************/
/* GUIDs */
#define EFI_FIRMWARE_FILE_SYSTEM2_GUID                          \
    ((EFI_GUID){ 0x8c8ce578, 0x8a3d, 0x4f1c,                    \
        { 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3 } })

#define EFI_FIRMWARE_FILE_SYSTEM3_GUID                          \
    ((EFI_GUID){ 0x5473c07a, 0x3dcb, 0x4dca,                    \
        { 0xbd, 0x6f, 0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a } })

#define EFI_SYSTEM_NV_DATA_FV_GUID                              \
    ((EFI_GUID){ 0xfff12b8d, 0x7696, 0x4c8b,                    \
        { 0xa9, 0x85, 0x27, 0x47, 0x7, 0x5b, 0x4f, 0x50 } })

#define EFI_FFS_VOLUME_TOP_FILE_GUID                            \
    ((EFI_GUID){ 0x1BA0062E, 0xC779, 0x4582,                    \
        { 0x85, 0x66, 0x33, 0x6A, 0xE8, 0xF7, 0x8F, 0x09 } })

/*
 * data structure for hob(Hand-Off block)
 * based on
 * UEFI Platform Initialization Specification Version 1.7. vol 3, chap 4 and 5
 */

#define EFI_HOB_TYPE_HANDOFF              0x0001
#define EFI_HOB_TYPE_MEMORY_ALLOCATION    0x0002
#define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR  0x0003
#define EFI_HOB_TYPE_GUID_EXTENSION       0x0004
#define EFI_HOB_TYPE_FV                   0x0005
#define EFI_HOB_TYPE_CPU                  0x0006
#define EFI_HOB_TYPE_MEMORY_POOL          0x0007
#define EFI_HOB_TYPE_FV2                  0x0009
#define EFI_HOB_TYPE_LOAD_PEIM_UNUSED     0x000A
#define EFI_HOB_TYPE_UEFI_CAPSULE         0x000B
#define EFI_HOB_TYPE_FV3                  0x000C
#define EFI_HOB_TYPE_UNUSED               0xFFFE
#define EFI_HOB_TYPE_END_OF_HOB_LIST      0xFFFF

typedef struct {
    uint16_t HobType;
    uint16_t HobLength;
    uint32_t Reserved;
} EFI_HOB_GENERIC_HEADER;


#define EFI_HOB_HANDOFF_TABLE_VERSION 0x0009

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    uint32_t Version;
    EFI_BOOT_MODE BootMode;
    EFI_PHYSICAL_ADDRESS EfiMemoryTop;
    EFI_PHYSICAL_ADDRESS EfiMemoryBottom;
    EFI_PHYSICAL_ADDRESS EfiFreeMemoryTop;
    EFI_PHYSICAL_ADDRESS EfiFreeMemoryBottom;
    EFI_PHYSICAL_ADDRESS EfiEndOfHobList;
} EFI_HOB_HANDOFF_INFO_TABLE;

typedef struct {
    EFI_GUID Name;
    EFI_PHYSICAL_ADDRESS MemoryBaseAddress;
    uint64_t MemoryLength;
    EFI_MEMORY_TYPE MemoryType;
    uint8_t Reserved[4];
} EFI_HOB_MEMORY_ALLOCATION_HEADER;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER AllocDescriptor;
} EFI_HOB_MEMORY_ALLOCATION;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER AllocDescriptor;
} EFI_HOB_MEMORY_ALLOCATION_STACK;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER AllocDescriptor;
} EFI_HOB_MEMORY_ALLOCATION_BSP_STORE;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_HOB_MEMORY_ALLOCATION_HEADER MemoryAllocationHeader;
    EFI_GUID ModuleName;
    EFI_PHYSICAL_ADDRESS EntryPoint;
} EFI_HOB_MEMORY_ALLOCATION_MODULE;

#define EFI_HOB_MEMORY_ALLOC_STACK_GUID                         \
    ((EFI_GUID){ 0x4ed4bf27, 0x4092, 0x42e9,                    \
        { 0x80, 0x7d, 0x52, 0x7b, 0x1d, 0x0, 0xc9, 0xbd } })

#define EFI_HOB_MEMORY_ALLOC_BSP_STORE_GUID                     \
    ((EFI_GUID){ 0x564b33cd, 0xc92a, 0x4593,                    \
        { 0x90, 0xbf, 0x24, 0x73, 0xe4, 0x3c, 0x63, 0x22 } })

#define EFI_HOB_MEMORY_ALLOC_MODULE_GUID                        \
    ((EFI_GUID){ 0xf8e21975, 0x899, 0x4f58,                     \
        { 0xa4, 0xbe, 0x55, 0x25, 0xa9, 0xc6, 0xd7, 0x7a } })


typedef uint32_t EFI_RESOURCE_TYPE;

#define EFI_RESOURCE_SYSTEM_MEMORY          0x00000000
#define EFI_RESOURCE_MEMORY_MAPPED_IO       0x00000001
#define EFI_RESOURCE_IO                     0x00000002
#define EFI_RESOURCE_FIRMWARE_DEVICE        0x00000003
#define EFI_RESOURCE_MEMORY_MAPPED_IO_PORT  0x00000004
#define EFI_RESOURCE_MEMORY_RESERVED        0x00000005
#define EFI_RESOURCE_IO_RESERVED            0x00000006
#define EFI_RESOURCE_MAX_MEMORY_TYPE        0x00000007

typedef uint32_t EFI_RESOURCE_ATTRIBUTE_TYPE;

#define EFI_RESOURCE_ATTRIBUTE_PRESENT                  0x00000001
#define EFI_RESOURCE_ATTRIBUTE_INITIALIZED              0x00000002
#define EFI_RESOURCE_ATTRIBUTE_TESTED                   0x00000004
#define EFI_RESOURCE_ATTRIBUTE_READ_PROTECTED           0x00000080

#define EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTED          0x00000100
#define EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTED      0x00000200
#define EFI_RESOURCE_ATTRIBUTE_PERSISTENT               0x00800000

#define EFI_RESOURCE_ATTRIBUTE_SINGLE_BIT_ECC           0x00000008
#define EFI_RESOURCE_ATTRIBUTE_MULTIPLE_BIT_ECC         0x00000010
#define EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_1           0x00000020
#define EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_2           0x00000040
#define EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE              0x00000400
#define EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE        0x00000800
#define EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE  0x00001000
#define EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE     0x00002000
#define EFI_RESOURCE_ATTRIBUTE_16_BIT_IO                0x00004000
#define EFI_RESOURCE_ATTRIBUTE_32_BIT_IO                0x00008000
#define EFI_RESOURCE_ATTRIBUTE_64_BIT_IO                0x00010000
#define EFI_RESOURCE_ATTRIBUTE_UNCACHED_EXPORTED        0x00020000
#define EFI_RESOURCE_ATTRIBUTE_READ_PROTECTABLE         0x00100000

#define EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTABLE        0x00200000
#define EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTABLE    0x00400000
#define EFI_RESOURCE_ATTRIBUTE_PERSISTABLE              0x01000000

#define EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTED      0x00040000
#define EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTABLE    0x00080000

#define EFI_RESOURCE_ATTRIBUTE_MORE_RELIABLE            0x02000000
#define EFI_RESOURCE_ATTRIBUTE_ENCRYPTED                0x04000000

/* FIXME: place holder for now */
#define EFI_RESOURCE_ATTRIBUTE_UNACCEPTED               0x00000000

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_GUID Owner;
    EFI_RESOURCE_TYPE ResourceType;
    EFI_RESOURCE_ATTRIBUTE_TYPE ResourceAttribute;
    EFI_PHYSICAL_ADDRESS PhysicalStart;
    uint64_t ResourceLength;
} EFI_HOB_RESOURCE_DESCRIPTOR;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_GUID Name;

    /* guid specific data follows */
} EFI_HOB_GUID_TYPE;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
} EFI_HOB_FIRMWARE_VOLUME;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
    EFI_GUID FvName;
    EFI_GUID FileName;
} EFI_HOB_FIRMWARE_VOLUME2;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
    uint32_t AuthenticationStatus;
    bool ExtractedFv;
    EFI_GUID FvName;
    EFI_GUID FileName;
} EFI_HOB_FIRMWARE_VOLUME3;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    uint8_t SizeOfMemorySpace;
    uint8_t SizeOfIoSpace;
    uint8_t Reserved[6];
} EFI_HOB_CPU;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
} EFI_HOB_MEMORY_POOL;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;

    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
} EFI_HOB_UEFI_CAPSULE;

#define EFI_HOB_OWNER_ZERO                                      \
    ((EFI_GUID){ 0x00000000, 0x0000, 0x0000,                    \
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } })

#endif
