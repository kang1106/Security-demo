/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "SPDU"
 * 	found in "SPDU.asn1"
 * 	`asn1c -gen-PER`
 */

#ifndef	_Elevation_H_
#define	_Elevation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Uint16.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Elevation */
typedef Uint16_t	 Elevation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Elevation;
asn_struct_free_f Elevation_free;
asn_struct_print_f Elevation_print;
asn_constr_check_f Elevation_constraint;
ber_type_decoder_f Elevation_decode_ber;
der_type_encoder_f Elevation_encode_der;
xer_type_decoder_f Elevation_decode_xer;
xer_type_encoder_f Elevation_encode_xer;
per_type_decoder_f Elevation_decode_uper;
per_type_encoder_f Elevation_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Elevation_H_ */
#include <asn_internal.h>
