/*******
	forward-auth supports two types of bearer token: application
	tokens, used by applications in the Docker Swarm when making
	HTTP requests and tenant tokens used by remote tenant client applications

	Tokens may be stored by token name as Docker secrets allowing direct
	access to the token value both by forward-auth and the calling application, or
	in the database, which requires either direct database access or client requests
	to an API exposing the token.

	Bearer tokens are referenced in access rules through calls to the forward-auth bearer() built-in.
	For example, in the following access rule expression the designated bearer token ROOT_TOKEN and
	the application token called MGT_TOKEN are resolved. If the bearer token in the request matches bearer()
	returns true.

	    "bearer('ROOT_TOKEN') || (bearer('MGT_TOKEN') && root())"

	Tenant bearer tokens are resolved by their tenant ID as follows:

	    "bearer(param(':tenantID'))"

	In this rule expression the call to bearer() returns true if the bearer token matches the tenant token
	for the value of tenantID found in the HTTP request path. Such a rule would allow a request for a tenant's widgets
	if the request was accompanied by the matching bearer token for that tenant ID:

	   GET .../foo-api/v1/tenants/{tenantID}/widgets)

	The tokens map associates bearer token values with their names (either an application short
	name or a tenantID):

	  |  TOKEN VALUE |  Application Token Name  (the application token name that is authorized to use the token)
	  |  TOKEN VALUE |  Tenant ID  (the tenant ID to which the token is assigned)


*******/

package fauth

type Application struct {
	Name   string `json:"name"`
	Bearer *Token `json:"bearer"`
}

type Tenant struct {
	Name      string     `json:"name"`
	Short     string     `json:"short"`
	GUID      string     `json:"guid"`
	Bearer    *Token     `json:"bearer"`
	PublicKey *PublicKey `json:"publicKey"`
}

type PublicKey struct {
	Source string `json:"source"`
	Value  string `json:"value,omitempty"`
}

type Token struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Root   bool   `json:"root"`
}
