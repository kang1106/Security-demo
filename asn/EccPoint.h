/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "SPDU"
 * 	found in "SPDU.asn1"
 * 	`asn1c -gen-PER`
 */

#ifndef	_EccPoint_H_
#define	_EccPoint_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <NULL.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EccPoint_PR {
	EccPoint_PR_NOTHING,	/* No components present */
	EccPoint_PR_x_only,
	EccPoint_PR_fill,
	EccPoint_PR_compressed_y_0,
	EccPoint_PR_compressed_y_1,
	EccPoint_PR_uncompressed
} EccPoint_PR;

/* EccPoint */
typedef struct EccPoint {
	EccPoint_PR present;
	union EccPoint_u {
		OCTET_STRING_t	 x_only;
		NULL_t	 fill;
		OCTET_STRING_t	 compressed_y_0;
		OCTET_STRING_t	 compressed_y_1;
		struct uncompressed {
			OCTET_STRING_t	 x;
			OCTET_STRING_t	 y;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} uncompressed;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EccPoint_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EccPoint;

#ifdef __cplusplus
}
#endif

#endif	/* _EccPoint_H_ */
#include <asn_internal.h>
