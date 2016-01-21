package com.arena.sso;

import org.pentaho.platform.web.http.security.HttpSessionReuseDetectionFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Enhanced filter for detection http session reuse.
 * Overrides requiresAuthentication method to make matching against the list of URLs specified by ssoFilterProcessing property.
 */
public class EnhancedHttpSessionReuseDetectionFilter extends HttpSessionReuseDetectionFilter {

    private String[] ssoFilterProcessesUrls;

    /**
     * {@inheritDoc}
     * <p>
     * Overrides super functionality to make the same check against several urls specified by ssoFilterProcessesUrls property.
     */
    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {

        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf( ';' );

        if ( pathParamIndex > 0 ) {
            // strip everything after the first semi-colon
            uri = uri.substring( 0, pathParamIndex );
        }

        boolean requiresSsoAuthentication = false;
        for (String processesUrl : ssoFilterProcessesUrls) {
            if(uri.endsWith(request.getContextPath() + processesUrl)) {
                requiresSsoAuthentication = true;
                break;
            }
        }

        return super.requiresAuthentication(request, response) || requiresSsoAuthentication;
    }

    public void setSsoFilterProcessesUrls(String[] ssoFilterProcessesUrls) {
        this.ssoFilterProcessesUrls = ssoFilterProcessesUrls;
    }
}
