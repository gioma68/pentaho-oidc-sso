package com.arena.sso.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;


/**
 * OAuth authentication token.
 */
public class OAuthAuthenticationToken extends AbstractAuthenticationToken {
    
    private static final Logger log = LoggerFactory.getLogger(OAuthAuthenticationToken.class);
    //~ Instance fields ================================================================================================

    private String identity;

    //~ Constructors ===================================================================================================

    public OAuthAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String identity) {
        super(authorities);
        this.identity = identity;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return identity;
    }

    @Override
    public Object getPrincipal() {
        return identity;
    }

    public String getIdentity() {
        return identity;
    }

}
