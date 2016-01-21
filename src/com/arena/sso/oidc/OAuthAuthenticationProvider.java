package com.arena.sso.oidc;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.util.Assert;


/**
 * Authentication provider to get UserDetails object using the identity of given OAuthPreAuthenticationToken as username,
 * and to create an authenticated OAuthAuthenticationToken. *
 */
public class OAuthAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    //~ Instance fields ================================================================================================

    private UserDetailsService userDetailsService;

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "The userDetailsService must be set");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        String identity = (String) authentication.getPrincipal();
        UserDetails userDetails = userDetailsService.loadUserByUsername(identity);

        return new OAuthAuthenticationToken(userDetails.getAuthorities(), identity);
    }

    @Override
    public boolean supports(Class authentication) {
        return OAuthPreAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
