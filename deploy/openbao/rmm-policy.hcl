# Scope for the RMM service identity. No root, system, seal, token creation,
# permanent destroy, metadata deletion, or unrelated provider paths.
path "rmm/data/northgate-rmm/endpoints/*" {
  capabilities = ["create", "read", "update"]
}
path "rmm/metadata/northgate-rmm/endpoints/*" {
  capabilities = ["create", "read", "update"]
}
path "rmm/delete/northgate-rmm/endpoints/*" {
  capabilities = ["update"]
}
path "rmm/undelete/northgate-rmm/endpoints/*" {
  capabilities = ["update"]
}
path "rmm/data/northgate-rmm/rotations/*" {
  capabilities = ["create", "read", "update"]
}
