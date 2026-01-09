package httpapi.authz

default allow = false

required_permission := sprintf("%s.%s", [input.resource, input.action])

allow if {
    raw_role := input.user.roles[_]
    user_role := upper(raw_role)

    role_perms := data.roles_permissions.roles[user_role]
    perm := role_perms[_]

    upper(perm) == upper(required_permission)
}
