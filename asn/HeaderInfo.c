/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "SPDU"
 * 	found in "SPDU.asn1"
 * 	`asn1c -gen-PER`
 */

#include "HeaderInfo.h"

static asn_TYPE_member_t asn_MBR_HeaderInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HeaderInfo, itsAid),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"itsAid"
		},
	{ ATF_POINTER, 5, offsetof(struct HeaderInfo, hashAlg),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HashAlgorithm,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"hashAlg"
		},
	{ ATF_POINTER, 4, offsetof(struct HeaderInfo, genTime),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Time64,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"genTime"
		},
	{ ATF_POINTER, 3, offsetof(struct HeaderInfo, expiryTime),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Time64,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"expiryTime"
		},
	{ ATF_POINTER, 2, offsetof(struct HeaderInfo, location),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ThreeDLocation,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"location"
		},
	{ ATF_POINTER, 1, offsetof(struct HeaderInfo, digest),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HashedId3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"digest"
		},
};
static const int asn_MAP_HeaderInfo_oms_1[] = { 1, 2, 3, 4, 5 };
static const ber_tlv_tag_t asn_DEF_HeaderInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_HeaderInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* itsAid */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* hashAlg */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* genTime */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* expiryTime */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* location */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* digest */
};
static asn_SEQUENCE_specifics_t asn_SPC_HeaderInfo_specs_1 = {
	sizeof(struct HeaderInfo),
	offsetof(struct HeaderInfo, _asn_ctx),
	asn_MAP_HeaderInfo_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_HeaderInfo_oms_1,	/* Optional members */
	5, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_HeaderInfo = {
	"HeaderInfo",
	"HeaderInfo",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_HeaderInfo_tags_1,
	sizeof(asn_DEF_HeaderInfo_tags_1)
		/sizeof(asn_DEF_HeaderInfo_tags_1[0]), /* 1 */
	asn_DEF_HeaderInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_HeaderInfo_tags_1)
		/sizeof(asn_DEF_HeaderInfo_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_HeaderInfo_1,
	6,	/* Elements count */
	&asn_SPC_HeaderInfo_specs_1	/* Additional specs */
};

