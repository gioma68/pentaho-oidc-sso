package com.arena.sso.oidc;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AbstractAuthenticationToken;


/**
 * OAuth authentication token.
 */
public class OAuthAuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ================================================================================================

    private String identity;

    //~ Constructors ===================================================================================================

    public OAuthAuthenticationToken(GrantedAuthority[] authorities, String identity) {
        super(authorities);
        this.identity = identity;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return identity;
    }

    public String getIdentity() {
        return identity;
    }

}
