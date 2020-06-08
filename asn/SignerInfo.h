/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "SPDU"
 * 	found in "SPDU.asn1"
 * 	`asn1c -gen-PER`
 */

#ifndef	_SignerInfo_H_
#define	_SignerInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "SequenceOfCertificate.h"
#include "CertificateDigest.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SignerInfo_PR {
	SignerInfo_PR_NOTHING,	/* No components present */
	SignerInfo_PR_self,
	SignerInfo_PR_certificate,
	SignerInfo_PR_certificateDigest
} SignerInfo_PR;

/* SignerInfo */
typedef struct SignerInfo {
	SignerInfo_PR present;
	union SignerInfo_u {
		NULL_t	 self;
		SequenceOfCertificate_t	 certificate;
		CertificateDigest_t	 certificateDigest;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SignerInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SignerInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _SignerInfo_H_ */
#include <asn_internal.h>
