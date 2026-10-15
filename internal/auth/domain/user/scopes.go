package user

type Scope string

const (
	ScopeDesignRead   Scope = "designs:read"
	ScopeDesignWrite  Scope = "designs:write"
	ScopeDesignDelete Scope = "designs:delete"
	ScopeDesignShare  Scope = "designs:share"
	ScopeBillingAdmin Scope = "billing:admin"
)

func ScopesToString(scopes []Scope) []string {
	res := make([]string, len(scopes))
	for i, s := range scopes {
		res[i] = string(s)
	}
	return res
}
