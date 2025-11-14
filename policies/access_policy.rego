package httpapi.authz

default allow := false

# Build the required permission from input
required_permission := sprintf("%s.%s", [input.resource, input.action])

allow if {
    # Extract roles from request
    raw_role := input.user.roles[_]

    # Normalize to uppercase
    user_role := upper(raw_role)
    print("role:", user_role)

    # Fetch permissions for the role from OPAL-synced data
    role_perms := data.result.roles[user_role]
    print("role perms:", role_perms)

    # Match each permission, case-insensitive
    perm := role_perms[_]
    print("checking perm:", perm)

    upper(perm) == upper(required_permission)
    print("required:", upper(required_permission))

    print("Allowed via role:", user_role, "permission:", perm)
}