package auth

import (
	"bitbucket.org/_metalogic_/pat"
)

// category constants as defined in database [auth].[CATEGORIES]
// TODO load services types, actions etc from database
const (
	// ADM admission applications admin category ***
	ADM = "ADM"
	// ADDR addresses admin category
	// access to institutions-api GLOBAL country, region address data
	// use INST category to allow an institution admin to manage own institution data including address
	ADDR = "ADDR"
	// API API admin category ***
	API = "API"
	// ATT file attachments admin category ***
	ATT = "ATT"
	// AUTH authentication/authorization admin category
	AUTH = "AUTH"
	// FEE fees admin category
	// access to fees-api
	FEE = "FEE"
	// INST institutions admin category
	INST = "INST"
	// MAIL mail admin category
	MAIL = "MAIL"
	// PASSWORD Password reset admin category
	PASSWORD = "PASSWORD"
	// PAYMENT Payment admin category
	PAYMENT = "PAYMENT"
	// PROG program data admin category ***
	PROG = "PROG"
	// QUESTION Question+Answer admin category
	QUESTION = "QUESTION"
	// ROLE Roles admin category
	ROLE = "ROLE"
	// RULE Rules admin category
	RULE = "RULE"
	// SERVICE Service admin category
	SERVICE = "SERVICE"
	// TRAN Transcripts admin category
	// access to institutions-api TX service config
	TRAN = "TRAN"
	// USER Transcripts admin category
	USER = "USER"
)

func APISmux(defaultStatus int) *pat.HostMux {
	hostMux := pat.NewHostMux(defaultStatus)

	// TODO
	var (
	// EPBC_API_TOKEN = ""
	// EPBCID    = "EPBC"
	// applToken = ""
	// mgtToken  = ""
	// signToken = ""
	)

	// rootHandler := BearerHandler(EPBC_API_TOKEN, nil)
	rootHandler := Eval("bearer(EPBC_API_TOKEN)")
	// tenantHandler := TenantHandler(":epbcID", rootHandler)

	// Applications API
	applMux := hostMux.AddPrefix("/applications-api/v1", pat.DenyHandler)
	applMux.Get("/", rootHandler)
	applMux.Get("/health", AllowHandler)
	applMux.Get("/info", rootHandler)
	applMux.Get("/stats", rootHandler)
	applMux.Get("/swagger/:any", rootHandler)
	applMux.Get("/admin/loglevel", rootHandler)
	applMux.Put("/admin/loglevel/:level", rootHandler)

	/*
		filesHandler := AnyBearerHandler([]string{EPBCID, applToken}, nil)
		applMux.Get("/files/:guid", filesHandler)
		applMux.Del("/files/:guid", filesHandler)

		applicationHandler := AllowDeny(tenantHandler, BearerHandler(mgtToken, nil), RoleHandler(":epbcID", ADM, nil))

		//TenantRoleHandler(":epbcID", applToken, ADM, tenantHandler)
		applMux.Get("/institutions/:epbcID/applications", applicationHandler)
		applMux.Get("/institutions/:epbcID/applications/:appNum", applicationHandler)
		applMux.Get("/institutions/:epbcID/applications/:appNum/answers", applicationHandler)
		applMux.Del("/institutions/:epbcID/applications/:appNum/answers", applicationHandler)
		applMux.Get("/institutions/:epbcID/applications/:appNum/answers/:guid", applicationHandler)
		applMux.Put("/institutions/:epbcID/applications/:appNum/answers/:guid", applicationHandler)
		applMux.Get("/institutions/:epbcID/applications/:appNum/fees", applicationHandler)
		applMux.Del("/institutions/:epbcID/applications/:appNum/fees", applicationHandler)
		applMux.Post("/institutions/:epbcID/applications/:appNum/fees", applicationHandler)
		applMux.Get("/institutions/:epbcID/applications/:appNum/files", applicationHandler)
		applMux.Post("/institutions/:epbcID/applications/:appNum/files", applicationHandler)
		applMux.Get("/institutions/:epbcID/applications/:appNum/files/:guid", applicationHandler)
		applMux.Del("/institutions/:epbcID/applications/:appNum/files/:guid", applicationHandler)
		applMux.Get("/institutions/:epbcID/contexts/:appNum", applicationHandler)

		// Auth API

		authHandler := AnyBearerHandler([]string{EPBCID, applToken, mgtToken, signToken}, nil)
		authTenantHandler := AllowDeny(authHandler, TenantHandler(":epbcID", nil))

		authMux := hostMux.AddPrefix("/auth-api/v1", pat.DenyHandler)
		authMux.Get("/", rootHandler)
		authMux.Get("/health", AllowHandler)
		authMux.Get("/info", rootHandler)
		authMux.Get("/stats", rootHandler)
		authMux.Get("/admin/loglevel", rootHandler)
		authMux.Put("/admin/loglevel/:level", rootHandler)

		// Auth Authentication
		authMux.Post("/login", AllowHandler)
		authMux.Post("/logout", AllowHandler)
		authMux.Get("/claims", AllowHandler)
		authMux.Post("/refreshtoken", rootHandler)

		// Auth Permission Categories
		authMux.Get("/actions", rootHandler)
		authMux.Get("/categories", rootHandler)
		authMux.Get("/categories/:name", rootHandler)

		// Auth Roles
		authMux.Get("/roles", rootHandler)
		authMux.Get("/roles/:guid", rootHandler)

		// Auth Invitations
		authMux.Get("/invitations", rootHandler)
		authMux.Get("/invitations/:token", rootHandler)
		authMux.Put("/invitations/:token", rootHandler)
		authMux.Post("/invitations", rootHandler)

		authMux.Get("/users", rootHandler)
		authMux.Post("/users", rootHandler)
		authMux.Get("/users/:guid", rootHandler)
		authMux.Put("/users/:guid", rootHandler)
		authMux.Del("/users/:guid", rootHandler)
		authMux.Get("/users/:guid/roles", rootHandler)

		// Auth User Roles
		authMux.Put("/users/:guid/roles/:roleguid", rootHandler)
		authMux.Del("/users/:guid/roles/:roleguid", rootHandler)

		// Auth Institution Roles
		authMux.Get("/institutions/:epbcid/roles", authTenantHandler)
		authMux.Post("/institutions/:epbcid/roles", authTenantHandler)
		authMux.Get("/institutions/:epbcid/roles/:roleguid", authTenantHandler)
		authMux.Put("/institutions/:epbcid/roles/:roleguid", authTenantHandler)
		authMux.Del("/institutions/:epbcid/roles/:roleguid", authTenantHandler)

		// Auth Institution Assigned Users
		authMux.Get("/institutions/:epbcid/users", authTenantHandler)
		authMux.Put("/institutions/:epbcid/users/:userguid", authTenantHandler)
		authMux.Del("/institutions/:epbcid/users/:userguid", authTenantHandler)

		// Auth Institution Assigned User Roles By User
		authMux.Get("/institutions/:epbcid/users/:userguid/roles", authTenantHandler)
		authMux.Put("/institutions/:epbcid/users/:userguid/roles/:roleguid", authTenantHandler)
		authMux.Del("/institutions/:epbcid/users/:userguid/roles/:roleguid", authTenantHandler)

		// Auth Institution Assigned User Roles By Role
		authMux.Get("/institutions/:epbcid/roles/:roleguid/users", authTenantHandler)
		authMux.Put("/institutions/:epbcid/roles/:roleguid/users/:userguid", authTenantHandler)
		authMux.Del("/institutions/:epbcid/roles/:roleguid/users/:userguid", authTenantHandler)

		// Auth Institution Permissions
		authMux.Post("/institutions/:epbcid/roles/:roleguid/permissions/:categorycode/:actioncode", authTenantHandler)
		authMux.Del("/institutions/:epbcid/roles/:roleguid/permissions/:categorycode/:actioncode", authTenantHandler)

		// Email API
		emailMux := hostMux.AddPrefix("/email-api/v1", pat.DenyHandler)
		emailMux.Get("/", rootHandler)
		emailMux.Post("/", rootHandler)
		emailMux.Get("/health", AllowHandler)
		emailMux.Get("/info", rootHandler)
		emailMux.Get("/stats", rootHandler)
		emailMux.Get("/admin/loglevel", rootHandler)
		emailMux.Put("/admin/loglevel/:level", rootHandler)

		// Fees API
		feesHandler := AnyBearerHandler([]string{EPBCID, applToken, mgtToken, signToken}, nil)
		feesTenantHandler := AllowDeny(feesHandler, TenantHandler(":epbcID", nil), RoleHandler(":epbcID", FEE, nil))
		feesMux := hostMux.AddPrefix("/fees-api/v1", pat.DenyHandler)
		feesMux.Get("/", rootHandler)
		feesMux.Get("/health", AllowHandler)
		feesMux.Get("/info", rootHandler)
		feesMux.Get("/stats", rootHandler)
		feesMux.Get("/admin/loglevel", rootHandler)
		feesMux.Put("/admin/loglevel/:level", rootHandler)

		// TODO fees.Get("/categories", AnyauthHandler)
		feesMux.Get("/categories", AllowHandler)

		// Fees Institution fees
		feesMux.Get("/institutions/:epbcID/fees", feesTenantHandler)
		feesMux.Post("/institutions/:epbcID/fees", feesTenantHandler)
		feesMux.Get("/institutions/:epbcID/fees/:guid", feesTenantHandler)
		feesMux.Put("/institutions/:epbcID/fees/:guid", feesTenantHandler)
		feesMux.Del("/institutions/:epbcID/fees/:guid", feesTenantHandler)
		feesMux.Get("/institutions/:epbcID/fees/:guid/feeSchedules", feesTenantHandler)
		feesMux.Put("/institutions/:epbcID/fees/:guid/feeSchedules", feesTenantHandler)

		// institutions-api
		institutionHandler := AnyBearerHandler([]string{EPBCID, applToken, mgtToken, signToken}, nil)
		institutionTenantHandler := AllowDeny(institutionHandler, TenantHandler(":epbcID", nil), RoleHandler(":epbcID", INST, nil))
		instMux := hostMux.AddPrefix("/institutions-api/v1", pat.DenyHandler)
		instMux.Get("/", rootHandler)
		instMux.Get("/health", AllowHandler)
		instMux.Get("/info", rootHandler)
		instMux.Get("/stats", rootHandler)
		instMux.Get("/swagger/:any", DenyHandler)
		instMux.Get("/admin/loglevel", rootHandler)
		instMux.Put("/admin/loglevel/:level", rootHandler)
		instMux.Put("/admin/cache/reload/:epbcid", rootHandler)

		instMux.Get("/address-types", DenyHandler)
		instMux.Get("/countries", DenyHandler)
		instMux.Get("/countries/:country", DenyHandler)
		instMux.Get("/countries/:country/regions", DenyHandler)
		instMux.Get("/countries/:country/regions/:region", DenyHandler)
		instMux.Get("/identifier-types", DenyHandler)
		instMux.Get("/institution-types", DenyHandler)
		instMux.Get("/institutions", rootHandler)
		instMux.Post("/institutions", rootHandler)

		// Institutions institutions
		instMux.Get("/institutions/:epbcID", institutionTenantHandler)
		instMux.Put("/institutions/:epbcID", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/addresses", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/addresses/:guid", institutionTenantHandler)
		instMux.Post("/institutions/:epbcID/addresses", institutionTenantHandler)
		instMux.Put("/institutions/:epbcID/addresses/:guid", institutionTenantHandler)
		instMux.Del("/institutions/:epbcID/addresses/:guid", institutionTenantHandler)
		// institution-assigned custom config
		instMux.Get("/institutions/:epbcID/custom/configs", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/custom/configs/:assignedEPBCID", institutionTenantHandler)
		instMux.Put("/institutions/:epbcID/custom/configs/:assignedEPBCID/:code", institutionTenantHandler)
		instMux.Del("/institutions/:epbcID/custom/configs/:assignedEPBCID/:code", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/custom/properties", institutionTenantHandler)
		instMux.Post("/institutions/:epbcID/custom/properties", institutionTenantHandler)
		instMux.Del("/institutions/:epbcID/custom/properties/:code", institutionTenantHandler)
		// institution identifiers
		instMux.Get("/institutions/:epbcID/identifiers", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/identifiers/:code", institutionTenantHandler)
		instMux.Put("/institutions/:epbcID/identifiers/:code/:value", rootHandler)
		instMux.Del("/institutions/:epbcID/identifiers/:code", rootHandler)
		instMux.Get("/institutions/:epbcID/info", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/payment-methods", institutionTenantHandler)
		instMux.Post("/institutions/:epbcID/payment-methods/:code", institutionTenantHandler)
		instMux.Del("/institutions/:epbcID/payment-methods/:code", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/roles", rootHandler)
		instMux.Post("/institutions/:epbcID/roles", rootHandler)
		instMux.Put("/institutions/:epbcID/roles/:role", rootHandler)
		instMux.Del("/institutions/:epbcID/roles/:role", rootHandler)
		instMux.Get("/institutions/:epbcID/services", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/services/:serviceType", institutionTenantHandler)
		instMux.Put("/institutions/:epbcID/services/:serviceType", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/services/:serviceType/configs", institutionTenantHandler)
		instMux.Get("/institutions/:epbcID/services/:serviceType/configs/:configKey", institutionTenantHandler)
		instMux.Put("/institutions/:epbcID/services/:serviceType/configs/:configKey", institutionTenantHandler)
		instMux.Get("/name-types", AllowHandler)
		instMux.Get("/services", AllowHandler)
		instMux.Get("/services/:serviceType", rootHandler)
		instMux.Post("/services/:serviceType", rootHandler)
		instMux.Get("/services/:serviceType/configs", rootHandler)
		instMux.Post("/services/:serviceType/configs", rootHandler)
		instMux.Get("/services/:serviceType/configs/:key", rootHandler)
		instMux.Del("/services/:serviceType/configs/:key", rootHandler)

		// mailer-api
		mailMux := hostMux.AddPrefix("/mailer-api/v1", pat.DenyHandler)
		mailMux.Get("/emails", rootHandler)
		mailMux.Get("/health", AllowHandler)
		mailMux.Get("/info", rootHandler)
		mailMux.Get("/stats", rootHandler)
		mailMux.Get("/swagger/:any", AllowHandler)
		mailMux.Get("/admin/loglevel", rootHandler)
		mailMux.Put("/admin/loglevel/:level", rootHandler)

		mailMux.Get("/emails", rootHandler) // TODO: Check if this is the correct handler?

		// passwordreset-api
		passMux := hostMux.AddPrefix("/passwordreset-api/v1", pat.DenyHandler)
		passMux.Get("/", rootHandler)
		passMux.Post("/", rootHandler)
		passMux.Get("/health", AllowHandler)
		passMux.Get("/info", rootHandler)
		passMux.Get("/stats", rootHandler)
		passMux.Get("/admin/loglevel", rootHandler)
		passMux.Put("/admin/loglevel/:level", rootHandler)

		passMux.Get("/:token", rootHandler)
		passMux.Put("/:token", rootHandler)

		// payments-api
		paymMux := hostMux.AddPrefix("/payments-api/v1", pat.DenyHandler)
		paymMux.Get("/", rootHandler)
		paymMux.Get("/health", AllowHandler)
		paymMux.Get("/info", rootHandler)
		paymMux.Get("/stats", rootHandler)
		paymMux.Get("/admin/loglevel", rootHandler)
		paymMux.Put("/admin/loglevel/:level", rootHandler)

		paymMux.Post("/payment-processing", rootHandler)
		paymMux.Get("/payment-url", rootHandler)
		paymMux.Get("/transactions", rootHandler)
		paymMux.Post("/transactions", rootHandler)
		paymMux.Get("/transactions/:id", rootHandler)
		paymMux.Put("/transactions/:id", rootHandler)
		paymMux.Del("/transactions/:id", rootHandler)

		// pdfapplications-api
		pdfaMux := hostMux.AddPrefix("/pdfapplications-api/v1", pat.DenyHandler)
		pdfaMux.Get("/", rootHandler)
		pdfaMux.Get("/health", AllowHandler)
		pdfaMux.Get("/info", rootHandler)
		pdfaMux.Get("/stats", rootHandler)
		pdfaMux.Get("/admin/loglevel", rootHandler)
		pdfaMux.Put("/admin/loglevel/:level", rootHandler)

		pdfaMux.Get("/receipts", rootHandler)
		pdfaMux.Post("/receipts", rootHandler)
		pdfaMux.Get("/receipts/:id", rootHandler)
		pdfaMux.Put("/receipts/:id", rootHandler)
		pdfaMux.Del("/receipts/:id", rootHandler)
		pdfaMux.Get("/receipts/:id/pdf", rootHandler)
		pdfaMux.Get("/receiptpdf", rootHandler)

		// person-api
		persMux := hostMux.AddPrefix("/person-api/v1", pat.DenyHandler)
		persMux.Get("/", rootHandler)
		persMux.Get("/health", AllowHandler)
		persMux.Get("/info", rootHandler)
		persMux.Get("/stats", rootHandler)
		persMux.Get("/admin/loglevel", rootHandler)
		persMux.Put("/admin/loglevel/:level", rootHandler)

		persMux.Get("/email", rootHandler)
		// Bad Form: /email/ is to work around access denied for GET /person-api/v1/email/?email=adam.brown%40educationplannerbc.ca etc
		persMux.Get("/email/", rootHandler)
		persMux.Post("/email", rootHandler)
		persMux.Put("/:personID/password", rootHandler)
		persMux.Put("/:token/confirm", rootHandler)

		// programselection-api
		progHandler := AnyBearerHandler([]string{EPBCID, applToken, mgtToken, signToken}, nil)
		progTenantHandler := AllowDeny(progHandler, TenantHandler(":epbcID", nil), RoleHandler(":epbcID", PROG, nil))
		progMux := hostMux.AddPrefix("/programselection-api/v1", pat.DenyHandler)
		progMux.Get("/health", AllowHandler)
		progMux.Get("/info", rootHandler)
		progMux.Get("/stats", rootHandler)
		progMux.Get("/admin/loglevel", rootHandler)
		progMux.Put("/admin/loglevel/:level", rootHandler)

		// Program selection institutions
		progMux.Get("/institutions/:epbcID/admissioncategories", progTenantHandler)
		progMux.Post("/institutions/:epbcID/admissioncategories", progTenantHandler)
		progMux.Get("/institutions/:epbcID/admissioncategories/:guid", progTenantHandler)
		progMux.Put("/institutions/:epbcID/admissioncategories/:guid", progTenantHandler)
		progMux.Del("/institutions/:epbcID/admissioncategories/:guid", progTenantHandler)
		progMux.Get("/institutions/:epbcID/campuses", progTenantHandler)
		progMux.Post("/institutions/:epbcID/campuses", progTenantHandler)
		progMux.Get("/institutions/:epbcID/campuses/:guid", progTenantHandler)
		progMux.Put("/institutions/:epbcID/campuses/:guid", progTenantHandler)
		progMux.Del("/institutions/:epbcID/campuses/:guid", progTenantHandler)
		progMux.Get("/institutions/:epbcID/faculties", progTenantHandler)
		progMux.Post("/institutions/:epbcID/faculties", progTenantHandler)
		progMux.Get("/institutions/:epbcID/faculties/:guid", progTenantHandler)
		progMux.Put("/institutions/:epbcID/faculties/:guid", progTenantHandler)
		progMux.Del("/institutions/:epbcID/faculties/:guid", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programs", progTenantHandler)
		progMux.Post("/institutions/:epbcID/programs", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programs/:guid", progTenantHandler)
		progMux.Put("/institutions/:epbcID/programs/:guid", progTenantHandler)
		progMux.Del("/institutions/:epbcID/programs/:guid", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programofferings", progTenantHandler)
		progMux.Post("/institutions/:epbcID/programofferings", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programofferings/:guid", progTenantHandler)
		progMux.Put("/institutions/:epbcID/programofferings/:guid", progTenantHandler)
		progMux.Del("/institutions/:epbcID/programofferings/:guid", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programofferingqualifiers", progTenantHandler)
		progMux.Post("/institutions/:epbcID/programofferingqualifiers", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programofferingqualifiers/:guid", progTenantHandler)
		progMux.Put("/institutions/:epbcID/programofferingqualifiers/:guid", progTenantHandler)
		progMux.Del("/institutions/:epbcID/programofferingqualifiers/:guid", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programofferingqualifiertypes", progTenantHandler)
		progMux.Get("/institutions/:epbcID/programofferingqualifiertypes/:guid", progTenantHandler)
		progMux.Get("/institutions/:epbcID/terms", progTenantHandler)
		progMux.Post("/institutions/:epbcID/terms", progTenantHandler)
		progMux.Get("/institutions/:epbcID/terms/:guid", progTenantHandler)
		progMux.Put("/institutions/:epbcID/terms/:guid", progTenantHandler)
		progMux.Del("/institutions/:epbcID/terms/:guid", progTenantHandler)

		// questions-api
		quesHandler := AnyBearerHandler([]string{EPBCID, applToken, mgtToken, signToken}, nil)
		quesTenantHandler := AllowDeny(quesHandler, TenantHandler(":epbcID", nil), RoleHandler(":epbcID", QUESTION, nil))
		quesMux := hostMux.AddPrefix("/questions-api/v1", pat.DenyHandler)
		quesMux.Get("/", rootHandler)
		quesMux.Get("/health", AllowHandler)
		quesMux.Get("/info", rootHandler)
		quesMux.Get("/stats", rootHandler)
		quesMux.Get("/admin/loglevel", rootHandler)
		quesMux.Put("/admin/loglevel/:level", rootHandler)

		// Questions institutions
		quesMux.Get("/questiontypes", rootHandler)
		quesMux.Post("/questiontypes", rootHandler)
		quesMux.Get("/questiontypes/:code", rootHandler)
		quesMux.Put("/questiontypes/:code", rootHandler)
		quesMux.Del("/questiontypes/:code", rootHandler)
		quesMux.Get("/institutions/:epbcID/groupingtypes", quesTenantHandler)
		quesMux.Post("/institutions/:epbcID/groupingtypes", quesTenantHandler)
		quesMux.Get("/institutions/:epbcID/groupingtypes/:guid", quesTenantHandler)
		quesMux.Put("/institutions/:epbcID/groupingtypes/:guid", quesTenantHandler)
		quesMux.Del("/institutions/:epbcID/groupingtypes/:guid", quesTenantHandler)
		quesMux.Get("/institutions/:epbcID/questions", quesTenantHandler)
		quesMux.Post("/institutions/:epbcID/questions", quesTenantHandler)
		quesMux.Put("/institutions/:epbcID/questions", quesTenantHandler)
		quesMux.Del("/institutions/:epbcID/questions", quesTenantHandler)
		quesMux.Get("/institutions/:epbcID/questions/:guid", quesTenantHandler)
		quesMux.Put("/institutions/:epbcID/questions/:guid", quesTenantHandler)
		quesMux.Del("/institutions/:epbcID/questions/:guid", quesTenantHandler)
		quesMux.Get("/institutions/:epbcID/questions/:guid/answers", quesTenantHandler)
		quesMux.Put("/institutions/:epbcID/questions/:guid/answers", quesTenantHandler)
		quesMux.Del("/institutions/:epbcID/questions/:guid/answers", quesTenantHandler)
		quesMux.Post("/institutions/:epbcID/questions/:guid/answers", quesTenantHandler)
		quesMux.Get("/institutions/:epbcID/questions/:guid/answers/:guid2", quesTenantHandler)
		quesMux.Put("/institutions/:epbcID/questions/:guid/answers/:guid2", quesTenantHandler)
		quesMux.Del("/institutions/:epbcID/questions/:guid/answers/:guid2", quesTenantHandler)

		// rules-api
		ruleHandler := AnyBearerHandler([]string{EPBCID, applToken, mgtToken, signToken}, nil)
		rulesTenantHandler := AllowDeny(ruleHandler, TenantHandler(":epbcID", nil), RoleHandler(":epbcID", RULE, nil))
		rulesMux := hostMux.AddPrefix("/rules-api/v1", pat.DenyHandler)
		rulesMux.Get("/", rootHandler)
		rulesMux.Get("/health", AllowHandler)
		rulesMux.Get("/info", rootHandler)
		rulesMux.Get("/stats", rootHandler)
		rulesMux.Get("/admin/loglevel", rootHandler)
		rulesMux.Put("/admin/loglevel/:level", rootHandler)

		rulesMux.Post("/evaluate/fees", rootHandler)
		rulesMux.Post("/evaluate/questions", rootHandler)
		rulesMux.Post("/evaluate/rules/:guid", rootHandler)
		rulesMux.Post("/finalize-fees-questions/:epbcID/:appNum", rootHandler)

		// Rules institutions
		rulesMux.Get("/institutions/:epbcID/extended-rules", rulesTenantHandler)
		rulesMux.Get("/institutions/:epbcID/rules", rulesTenantHandler)
		rulesMux.Post("/institutions/:epbcID/rules", rulesTenantHandler)
		rulesMux.Get("/institutions/:epbcID/rules/:ID", rulesTenantHandler)
		rulesMux.Put("/institutions/:epbcID/rules/:ID", rulesTenantHandler)
		rulesMux.Del("/institutions/:epbcID/rules/:ID", rulesTenantHandler)
		rulesMux.Post("/institutions/:epbcID/evaluate/rules/:ID", rulesTenantHandler)
		rulesMux.Get("/rules", rootHandler)
		rulesMux.Get("/rules/:ID", rootHandler)

		// user-profiles-api
		uprofMux := hostMux.AddPrefix("/user-profiles-api/v1", pat.DenyHandler)
		uprofMux.Get("/", rootHandler)
		uprofMux.Get("/health", AllowHandler)
		uprofMux.Get("/info", rootHandler)
		uprofMux.Get("/stats", rootHandler)
		uprofMux.Get("/admin/loglevel", rootHandler)
		uprofMux.Put("/admin/loglevel/:level", rootHandler)
	*/
	return hostMux
}
