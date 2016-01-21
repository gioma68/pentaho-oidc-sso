package com.arena.sso.oidc;

import com.arena.sso.oidc.consumer.OAuthConsumer;
import com.arena.sso.oidc.consumer.OAuthConsumerException;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.security.util.RedirectUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * AuthenticationEntryPoint is handle request witch wants to login via oauth providers.
 * Creates the url and redirect user to oauth provider's endpoint.
 */
public class OAuthAuthenticationEntryPoint extends SpringSecurityFilter implements AuthenticationEntryPoint {

    //~ Static fields ==================================================================================================

    /**
     * Default name of path suffix which will invoke this filter.
     */
    private static final String DEFAUL_FILTER_URL = "/j_spring_oauth_security_check";

    //~ Instance fields ================================================================================================

    /**
     * User configured path which overrides the default value.
     */
    private String filterProcessesUrl;


    private OAuthConsumer consumer;
    //~ Methods ========================================================================================================

    /**
     * The filter will be used in case the URL of the request ends with DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request) {
        if (filterProcessesUrl != null) {
            return (request.getRequestURI().endsWith(filterProcessesUrl));
        } else {
            return (request.getRequestURI().endsWith(DEFAUL_FILTER_URL));
        }
    }


    /**
     * Handle request and create url to redirect to social.
     * @param request          request
     * @param response         response
     * @param authException    exception causing this entry point to be invoked
     * @throws java.io.IOException     error sending response
     * @throws javax.servlet.ServletException
     */
    @Override
    public void commence(ServletRequest request, ServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        try {
            String url = consumer.handleLoginRequest((HttpServletRequest) request);
            sendRedirect((HttpServletRequest) request, (HttpServletResponse) response, url);
        } catch (OAuthConsumerException e) {
            e.printStackTrace();
        }
    }

    /**
     * In case the DEFAULT_FILTER_URL is invoked directly, the filter will get called and initialize the
     * login sequence.
     */
    @Override
    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (processFilter(request)) {
            commence(request, response, null);
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public int getOrder() {
        return FilterChainOrder.PRE_AUTH_FILTER + 20;
    }


    protected void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url)
            throws IOException {

        RedirectUtils.sendRedirect(request, response, url, false);
    }


    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public OAuthConsumer getConsumer() {
        return consumer;
    }

    public void setConsumer(OAuthConsumer consumer) {
        this.consumer = consumer;
    }
}
