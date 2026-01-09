package httpapi.authz

default allow := false

required_permission := sprintf("%s.%s", [input.resource, input.action])

allow if {
	raw_role := input.user.roles[_]
	user_role := lower(raw_role)
	print("User role:", user_role)

	role_perms := data.roles_permissions.roles[user_role]
	print("Permissions for role:", role_perms)

	perm := role_perms[_]
	print("Checking permission:", perm)

	print("Required permission:", required_permission)

	perm == required_permission
}

