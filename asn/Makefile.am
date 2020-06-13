ASN_MODULE_SRC=	\
	SecuredMessage.c	\
	Payload.c	\
	SignedData.c	\
	SignerInfo.c	\
	SequenceOfCertificate.c	\
	Certificate.c	\
	IssuerID.c	\
	CertificateDigest.c	\
	HashAlgorithm.c	\
	TBSCert.c	\
	SubjectInfo.c	\
	SubjectType.c	\
	SubjectAttributes.c	\
	PublicVerifyKey.c	\
	EccCurve.c	\
	EccPoint.c	\
	Signature.c	\
	TBSData.c	\
	HeaderInfo.c	\
	ThreeDLocation.c	\
	Latitude.c	\
	NinetyDegreeInt.c	\
	KnownLatitude.c	\
	UnKnownLatitude.c	\
	Longitude.c	\
	OneEightyDegreeInt.c	\
	KnownLongitude.c	\
	UnKnownLongitude.c	\
	Elevation.c	\
	Uint3.c	\
	Uint8.c	\
	Uint16.c	\
	Uint32.c	\
	Uint64.c	\
	HashedId3.c	\
	HashedId8.c	\
	Opaque.c	\
	Time32.c	\
	Time64.c

ASN_MODULE_HEAD=	\
	SecuredMessage.h	\
	Payload.h	\
	SignedData.h	\
	SignerInfo.h	\
	SequenceOfCertificate.h	\
	Certificate.h	\
	IssuerID.h	\
	CertificateDigest.h	\
	HashAlgorithm.h	\
	TBSCert.h	\
	SubjectInfo.h	\
	SubjectType.h	\
	SubjectAttributes.h	\
	PublicVerifyKey.h	\
	EccCurve.h	\
	EccPoint.h	\
	Signature.h	\
	TBSData.h	\
	HeaderInfo.h	\
	ThreeDLocation.h	\
	Latitude.h	\
	NinetyDegreeInt.h	\
	KnownLatitude.h	\
	UnKnownLatitude.h	\
	Longitude.h	\
	OneEightyDegreeInt.h	\
	KnownLongitude.h	\
	UnKnownLongitude.h	\
	Elevation.h	\
	Uint3.h	\
	Uint8.h	\
	Uint16.h	\
	Uint32.h	\
	Uint64.h	\
	HashedId3.h	\
	HashedId8.h	\
	Opaque.h	\
	Time32.h	\
	Time64.h

ASN_MODULE_HEAD+=BOOLEAN.h
ASN_MODULE_SRC+=BOOLEAN.c
ASN_MODULE_HEAD+=INTEGER.h
ASN_MODULE_HEAD+=NativeEnumerated.h
ASN_MODULE_SRC+=INTEGER.c
ASN_MODULE_HEAD+=NULL.h
ASN_MODULE_SRC+=NULL.c
ASN_MODULE_SRC+=NativeEnumerated.c
ASN_MODULE_HEAD+=NativeInteger.h
ASN_MODULE_SRC+=NativeInteger.c
ASN_MODULE_HEAD+=asn_SEQUENCE_OF.h
ASN_MODULE_SRC+=asn_SEQUENCE_OF.c
ASN_MODULE_HEAD+=asn_SET_OF.h
ASN_MODULE_SRC+=asn_SET_OF.c
ASN_MODULE_HEAD+=constr_CHOICE.h
ASN_MODULE_SRC+=constr_CHOICE.c
ASN_MODULE_HEAD+=constr_SEQUENCE.h
ASN_MODULE_SRC+=constr_SEQUENCE.c
ASN_MODULE_HEAD+=constr_SEQUENCE_OF.h
ASN_MODULE_SRC+=constr_SEQUENCE_OF.c
ASN_MODULE_HEAD+=constr_SET_OF.h
ASN_MODULE_SRC+=constr_SET_OF.c
ASN_MODULE_HEAD+=asn_application.h
ASN_MODULE_HEAD+=asn_system.h
ASN_MODULE_HEAD+=asn_codecs.h
ASN_MODULE_HEAD+=asn_internal.h
ASN_MODULE_HEAD+=OCTET_STRING.h
ASN_MODULE_SRC+=OCTET_STRING.c
ASN_MODULE_HEAD+=BIT_STRING.h
ASN_MODULE_SRC+=BIT_STRING.c
ASN_MODULE_SRC+=asn_codecs_prim.c
ASN_MODULE_HEAD+=asn_codecs_prim.h
ASN_MODULE_HEAD+=ber_tlv_length.h
ASN_MODULE_SRC+=ber_tlv_length.c
ASN_MODULE_HEAD+=ber_tlv_tag.h
ASN_MODULE_SRC+=ber_tlv_tag.c
ASN_MODULE_HEAD+=ber_decoder.h
ASN_MODULE_SRC+=ber_decoder.c
ASN_MODULE_HEAD+=der_encoder.h
ASN_MODULE_SRC+=der_encoder.c
ASN_MODULE_HEAD+=constr_TYPE.h
ASN_MODULE_SRC+=constr_TYPE.c
ASN_MODULE_HEAD+=constraints.h
ASN_MODULE_SRC+=constraints.c
ASN_MODULE_HEAD+=xer_support.h
ASN_MODULE_SRC+=xer_support.c
ASN_MODULE_HEAD+=xer_decoder.h
ASN_MODULE_SRC+=xer_decoder.c
ASN_MODULE_HEAD+=xer_encoder.h
ASN_MODULE_SRC+=xer_encoder.c
ASN_MODULE_HEAD+=per_support.h
ASN_MODULE_SRC+=per_support.c
ASN_MODULE_HEAD+=per_decoder.h
ASN_MODULE_SRC+=per_decoder.c
ASN_MODULE_HEAD+=per_encoder.h
ASN_MODULE_SRC+=per_encoder.c
ASN_MODULE_HEAD+=per_opentype.h
ASN_MODULE_SRC+=per_opentype.c


lib_LTLIBRARIES=libasn.la
libasn_la_CFLAGS = -I.
libasn_la_SOURCES=$(ASN_MODULE_SRC) $(ASN_MODULE_HEAD)
