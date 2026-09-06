package com.northgate.rmm;

import org.keycloak.protocol.oidc.mappers.AmrProtocolMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;

/** Exposes Keycloak's completed-authenticator AMR calculation to introspection. */
public final class IntrospectableAmrMapper extends AmrProtocolMapper
        implements TokenIntrospectionTokenMapper {
    @Override
    public String getId() {
        return "northgate-amr-introspection";
    }

    @Override
    public String getDisplayType() {
        return "NorthGate AMR with introspection";
    }
}
