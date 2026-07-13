package app

import "github.com/imkerbos/mxid/pkg/errcode"

// Business codes for the app domain, declared next to the sentinels they map.
// The numeric values are the frozen API contract — unchanged from the former
// handleServiceError switch (see pkg/errcode). response.MapError does the lookup.
var (
	codeAppNotFound        = errcode.Code{HTTP: 404, Num: 40401}
	codeAppGroupNotFound   = errcode.Code{HTTP: 404, Num: 40402}
	codeAccessNotFound     = errcode.Code{HTTP: 404, Num: 40403}
	codeCertNotFound       = errcode.Code{HTTP: 404, Num: 40404}
	codeAccountNotFound    = errcode.Code{HTTP: 404, Num: 40405}
	codeSubjectNotInTenant = errcode.Code{HTTP: 404, Num: 40406}
	codeTemplateNotFound   = errcode.Code{HTTP: 404, Num: 40407}
	codeAppCodeExists      = errcode.Code{HTTP: 409, Num: 40901}
	codeGroupCodeExists    = errcode.Code{HTTP: 409, Num: 40902}
	codeInvalidClientType  = errcode.Code{HTTP: 400, Num: 40010}
	codeFormFillNotLicensed = errcode.Code{HTTP: 403, Num: 40301}
)

func init() {
	errcode.Bind(ErrAppNotFound, codeAppNotFound)
	errcode.Bind(ErrAppGroupNotFound, codeAppGroupNotFound)
	errcode.Bind(ErrAccessNotFound, codeAccessNotFound)
	errcode.Bind(ErrCertNotFound, codeCertNotFound)
	errcode.Bind(ErrAccountNotFound, codeAccountNotFound)
	errcode.Bind(ErrSubjectNotInTenant, codeSubjectNotInTenant)
	errcode.Bind(ErrTemplateNotFound, codeTemplateNotFound)
	errcode.Bind(ErrAppCodeExists, codeAppCodeExists)
	errcode.Bind(ErrGroupCodeExists, codeGroupCodeExists)
	errcode.Bind(ErrInvalidClientType, codeInvalidClientType)
	errcode.Bind(ErrFormFillNotLicensed, codeFormFillNotLicensed)
}
