#ifndef XO_MK_IMAGE_H
#define XO_MK_IMAGE_H 1

#define XO_CURRENT_HDR_VERSION 0

/*
 * The format of the file downloaded is as follows:
 *
 *   GLOBAL HEADER
 *   IMAGE HEADER #1
 *   IMAGE HEADER #2
 *   ...
 *   IMAGE HEADER #n
 *   RAW DATA
 *
 *  where raw data is the concatenation of all images.
 */

struct GlobalHdr
{
	uint32_t hdr_version;  /* header version       */
	uint32_t nimages;      /* Number of images     */
	uint32_t raw_size;     /* length of raw data combining all images  */
	char this_version[32];  // firmware version in this file
	char min_version[32];  //  minimum version required to upgrade to this file.  Allows forcing upgrade to version 2 before upgrade to version 3
	uint8_t digest[16];    /* md5sum over raw data */
};

enum ProductType {
	ProductType_invalid = 0, // unset
	ProductType_ExoKey_v1 = 1,
	ProductType_ExoNet_xo1 = 2,
	ProductType_last  // Last /invalid
};


struct GlobalHdr_v1
{
	uint32_t hdr_version;  /* header version       */
	uint32_t nimages;      /* Number of images     */
	uint32_t raw_size;     /* length of raw data combining all images  */
	char this_version[32];  // firmware version in this file
	char min_version[32];  //  minimum version required to upgrade to this file.  Allows forcing upgrade to version 2 before upgrade to version 3
	uint32_t product_type_code;  // avoid writing wrong product
	uint8_t sha256[32];    /* sha256 over raw data */
	uint8_t signature[256];    /* sign file */

};

enum PartType {
	PartType_invalid = 0, // unset
	PartType_MtdPart = 1,  // MTD partition
	PartType_ubiVolume = 2, // Ubi volume
	PartType_raw = 3,  // raw image with offset used from 0 of Flash device
	PartType_file = 4,  // file on a file system
	
	PartType_last  // Last /invalid
};

struct ImageHeader
{
	enum PartType part_type;
	int32_t partition;    // MTD partition number or  UBI partition
	uint32_t size;         /* Length of image data */
	uint32_t offset;  // Offset to start writing.  NOTE not used now, possible future use
	char devname[32];    // UBI device, MTD device, or block device
	char filename[32];   // PartType_ubiVolume==UBI Volume name,  PartType_file==file path
};

#endif
/* EOF */

