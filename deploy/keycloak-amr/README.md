# Keycloak 26.7.3 AMR introspection adapter

Keycloak 26.7.3's built-in `AmrProtocolMapper` emits authentication method
references into access and ID tokens but does not implement
`TokenIntrospectionTokenMapper`. RMM verifies sessions through online
introspection and requires `amr` to contain `otp`.

This provider extends the installed Keycloak AMR mapper and adds that interface
under a distinct provider ID. It inherits Keycloak's existing introspection
implementation, completed-authenticator calculation and expiry checks. It does
not invent an OTP claim, inspect OTP credentials or weaken RMM authorization.

## Build and test

Use a JDK supporting Java 17 and an unpacked Keycloak 26.7.3 distribution:

```sh
sh build.sh /opt/keycloak-26.7.3 /tmp/new-amr-build
```

The script compiles against the distribution's own libraries and exercises the
real mapper with synthetic sessions. It checks valid, missing, expired and
uncompleted OTP authentication, and a disabled introspection mapping. The
resulting JAR contains only the adapter class and its provider registration.

## Install

Stop the identity provider, preserve its current optimized build and client
mapper configuration, and copy `northgate-amr-introspection.jar` to its
`providers/` directory. Run `kc.sh build` using the deployment's existing build
options, then restart normally. No custom VM or container image is required.

Select `northgate-amr-introspection` for the RMM client's `amr` mapper, retaining
`introspection.token.claim`, `access.token.claim` and `id.token.claim` as `true`.
Set the password and OTP executions' `default.reference.maxAge` to the enforced
session limit, such as `28800` seconds for eight hours. An omitted value defaults
to zero in this Keycloak version.

Verify owner login and refreshed sessions through RMM; verify an invalid token
still fails. Do not substitute account enrollment or ACR alone for the OTP claim.
For rollback, restore the previous client mapper and optimized build, and remove
only this provider JAR. Requalify the adapter when changing Keycloak versions.

Implementation references:
[AMR mapper](https://github.com/keycloak/keycloak/blob/26.7.3/services/src/main/java/org/keycloak/protocol/oidc/mappers/AmrProtocolMapper.java),
[AMR expiry calculation](https://github.com/keycloak/keycloak/blob/26.7.3/services/src/main/java/org/keycloak/protocol/oidc/utils/AmrUtils.java).
