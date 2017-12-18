package com.arena.sso.oidc;

import com.arena.sso.oidc.consumer.OAuthConsumer;
import com.arena.sso.oidc.consumer.OAuthConsumerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.GenericFilterBean;

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
public class OAuthAuthenticationEntryPoint extends GenericFilterBean implements AuthenticationEntryPoint
{
    private static final Logger log = LoggerFactory.getLogger(OAuthAuthenticationEntryPoint.class);
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
    
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    /**
     * The filter will be used in case the URL of the request ends with DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request)
    {
        if (filterProcessesUrl != null)
        {
            return (request.getRequestURI().endsWith(filterProcessesUrl));
        }
        else
        {
            return (request.getRequestURI().endsWith(DEFAUL_FILTER_URL));
        }
    }
    
    
    /**
     * Handle request and create url to redirect to social.
     *
     * @param request       request
     * @param response      response
     * @param authException exception causing this entry point to be invoked
     * @throws IOException            error sending response
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException
    {
        try
        {
            String url = consumer.handleLoginRequest(request);
            sendRedirect(request, response, url);
        }
        catch (OAuthConsumerException ex)
        {
            log.error("Error during create redirect url. ", ex);
        }
    }
    
    /**
     * In case the DEFAULT_FILTER_URL is invoked directly, the filter will get called and initialize the
     * login sequence.
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException
    {
        if (processFilter((HttpServletRequest)servletRequest))
        {
            log.info("Entry Point filter triggered url: {}", DEFAUL_FILTER_URL);
            commence((HttpServletRequest)servletRequest, (HttpServletResponse)servletResponse, null);
        }
        else
        {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
    
    protected void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url)
            throws IOException
    {
        log.info("Send redirect to {}", url);
        redirectStrategy.sendRedirect(request, response, url);
    }
    
    public RedirectStrategy getRedirectStrategy()
    {
        return redirectStrategy;
    }
    
    public void setRedirectStrategy(RedirectStrategy redirectStrategy)
    {
        this.redirectStrategy = redirectStrategy;
    }
    
    public String getFilterProcessesUrl()
    {
        return filterProcessesUrl;
    }
    
    public void setFilterProcessesUrl(String filterProcessesUrl)
    {
        this.filterProcessesUrl = filterProcessesUrl;
    }
    
    public OAuthConsumer getConsumer()
    {
        return consumer;
    }
    
    public void setConsumer(OAuthConsumer consumer)
    {
        this.consumer = consumer;
    }
}
