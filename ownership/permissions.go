// Package ownership holds the rules for acting for an owner: handles, and the
// permissions members hold in an organization. It has no storage; callers pass
// in the grants they loaded.
package ownership

// Permission is one thing a member may do for an organization.
type Permission string

const (
	OrganizationManage Permission = "organization.manage"
	MembersManage      Permission = "members.manage"
	DomainsManage      Permission = "domains.manage"
	AppsCreate         Permission = "apps.create"
	SchemasPublish     Permission = "schemas.publish"
	AuditView          Permission = "audit.view"
	AppsEdit           Permission = "apps.edit"
	AppsSecrets        Permission = "apps.secrets"
	AppsDelete         Permission = "apps.delete"
	AppsReview         Permission = "apps.review"
	UsageView          Permission = "usage.view"
)

// organizationOnly permissions cannot be limited to one app.
var organizationOnly = map[Permission]bool{
	OrganizationManage: true,
	MembersManage:      true,
	DomainsManage:      true,
	AppsCreate:         true,
	SchemasPublish:     true,
	AuditView:          true,
}

var perApp = map[Permission]bool{
	AppsEdit:    true,
	AppsSecrets: true,
	AppsDelete:  true,
	AppsReview:  true,
	UsageView:   true,
}

// AllPermissions lists every permission, organization-only ones first.
var AllPermissions = []Permission{
	OrganizationManage, MembersManage, DomainsManage, AppsCreate, SchemasPublish, AuditView,
	AppsEdit, AppsSecrets, AppsDelete, AppsReview, UsageView,
}

// PerAppPermissions are the permissions a member gets on an app they create.
var PerAppPermissions = []Permission{AppsEdit, AppsSecrets, AppsDelete, AppsReview, UsageView}

// Grant is a permission with its reach: the whole organization when AppID is
// nil, otherwise the one app (OAuth client) it names.
type Grant struct {
	Permission Permission `json:"permission"`
	AppID      *string    `json:"appId"`
}

// OrganizationWide is a grant of permission over the whole organization.
func OrganizationWide(permission Permission) Grant {
	return Grant{Permission: permission}
}

// ForApp is a grant of permission over one app.
func ForApp(permission Permission, appID string) Grant {
	return Grant{Permission: permission, AppID: &appID}
}

// IsKnown reports whether the permission exists.
func IsKnown(permission Permission) bool {
	return organizationOnly[permission] || perApp[permission]
}

// IsValid reports whether the grant names a known permission with a reach it
// allows: organization-only permissions never name an app.
func (grant Grant) IsValid() bool {
	if !IsKnown(grant.Permission) {
		return false
	}
	if grant.AppID == nil {
		return true
	}
	return perApp[grant.Permission] && *grant.AppID != ""
}

// Covers reports whether holding this grant includes wanted: the same
// permission, at the same or a wider reach.
func (grant Grant) Covers(wanted Grant) bool {
	if grant.Permission != wanted.Permission {
		return false
	}
	if grant.AppID == nil {
		return true
	}
	return wanted.AppID != nil && *wanted.AppID == *grant.AppID
}

func sameGrant(first Grant, second Grant) bool {
	return first.Covers(second) && second.Covers(first)
}

// Allows reports whether any of the grants covers permission for appID; an
// empty appID asks for the organization-wide permission.
func Allows(grants []Grant, permission Permission, appID string) bool {
	wanted := OrganizationWide(permission)
	if appID != "" {
		wanted = ForApp(permission, appID)
	}
	return coveredBy(grants, wanted)
}

func coveredBy(grants []Grant, wanted Grant) bool {
	for _, grant := range grants {
		if grant.Covers(wanted) {
			return true
		}
	}
	return false
}

// AllGrants is every permission over the whole organization, held by an
// organization's creator and by a person acting for their own handle.
func AllGrants() []Grant {
	grants := make([]Grant, 0, len(AllPermissions))
	for _, permission := range AllPermissions {
		grants = append(grants, OrganizationWide(permission))
	}
	return grants
}

// Normalize drops duplicates and grants already covered by a wider one, so a
// stored grant list stays minimal.
func Normalize(grants []Grant) []Grant {
	normalized := []Grant{}
	for index, grant := range grants {
		if coveredByOther(grants, index) {
			continue
		}
		normalized = append(normalized, grant)
	}
	return normalized
}

// coveredByOther reports whether another grant covers grants[index]; of two
// identical grants only the first is kept.
func coveredByOther(grants []Grant, index int) bool {
	for otherIndex, other := range grants {
		if otherIndex == index || !other.Covers(grants[index]) {
			continue
		}
		if !sameGrant(other, grants[index]) || otherIndex < index {
			return true
		}
	}
	return false
}
