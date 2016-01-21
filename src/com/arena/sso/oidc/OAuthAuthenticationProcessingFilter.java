package com.arena.sso.oidc;

import com.arena.sso.oidc.consumer.OAuthConsumerException;
import com.arena.sso.oidc.consumer.OAuthConsumerImpl;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;

import javax.servlet.http.HttpServletRequest;


/**
 * Filter processes request coming from OAuth provider and delegating to the OauthConsumer. After the OAuthPreAuthenticationToken
 * is obtained, authentication providers are asked to authenticate it.
 *
 */
public class OAuthAuthenticationProcessingFilter extends AbstractProcessingFilter {

    //~ Static fields ==================================================================================================

    private static final String DEFAUL_URL = "/oauth/authenticate";

    //~ Instance fields ================================================================================================

    private OAuthConsumerImpl consumer;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        if (consumer == null) {
            consumer = new OAuthConsumerImpl(DEFAUL_URL);
        }
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        OAuthPreAuthenticationToken preAuthToken;
        try {
            String identity = consumer.handleAuthenticationRequest(request);
            preAuthToken = new OAuthPreAuthenticationToken(identity);
        } catch (OAuthConsumerException oce) {
            throw new AuthenticationServiceException("Consumer error", oce);
        } catch (Exception e) {
            throw new AuthenticationServiceException("Consumer error", e);
        }

        preAuthToken.setDetails(authenticationDetailsSource.buildDetails(request));

        // delegate to the auth provider
        return getAuthenticationManager().authenticate(preAuthToken);
    }

    @Override
    public String getDefaultFilterProcessesUrl() {
        return DEFAUL_URL;
    }

    @Override
    public int getOrder() {
        return FilterChainOrder.AUTHENTICATION_PROCESSING_FILTER + 20;
    }

    public OAuthConsumerImpl getConsumer() {
        return consumer;
    }

    public void setConsumer(OAuthConsumerImpl consumer) {
        this.consumer = consumer;
    }
}
