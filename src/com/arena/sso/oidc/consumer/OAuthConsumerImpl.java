package com.arena.sso.oidc.consumer;

import com.arena.sso.oidc.OAuthAuthenticationToken;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.*;
import org.scribe.oauth.OAuthService;
import org.springframework.beans.factory.InitializingBean;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import static java.lang.System.out;

public class OAuthConsumerImpl implements OAuthConsumer, InitializingBean {
	
	//~ Instance fields ================================================================================================
	
	private String redirectUrl;
	
	/* mitreid custom prop	*/
	private String mitreoidConsumerKey;
	private String mitreoidConsumerSecret;
	private String mitreoidTokenRequestUri;
	private String mitreoidAccessTokenUri;
	private String mitreoidAuthenticationTokenUri;
	private String mitreOpenIdClaim;
	/* wso2is custom prop	*/
	private String wso2isConsumerKey;
	private String wso2isConsumerSecret;
	private String wso2isTokenRequestUri;
	private String wso2isAccessTokenUri;
	private String wso2isAuthenticationTokenUri;
	private String wso2OpenIdClaim;
	
	public OAuthService service;
	
	//~ Constructor ====================================================================================================
	
	public OAuthConsumerImpl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}
	
	//~ Methods ========================================================================================================
	
	@Override
	public void afterPropertiesSet() throws Exception {
	}
	
	@Override
	public String handleLoginRequest(HttpServletRequest request) throws OAuthConsumerException {

		String responseType = "code";
		String issuer = request.getParameter("issuer");
		String url = null;
		
		if(issuer.equals("mitreoid")) {
			String consumer_key = mitreoidConsumerKey;
			String token_request_uri = mitreoidTokenRequestUri;
			String scope = "openid+"+mitreOpenIdClaim;
			String state = "mitreoid";
			// mitreid connect first step don't require grant_type
			url = String.format("%s?response_type=%s&client_id=%s&scope=%s&state=%s&redirect_uri=%s",
			    token_request_uri, responseType, consumer_key, scope, state, redirectUrl);
			
		} else if(issuer.equals("wso2is")) {
			String consumer_key = wso2isConsumerKey;
			String token_request_uri = wso2isTokenRequestUri;
			String scope = "openid";
			String state = "wso2is";
			String prompt = "login"; //force always the login form
			String grant_type = "authorization_code";
			
			url = String.format("%s?response_type=%s&client_id=%s&redirect_uri=%s&grant_type=%s&scope=%s&state=%s&prompt=%s",
			    token_request_uri, responseType, consumer_key, redirectUrl, grant_type, scope, state, prompt);
		
		} else { // issuer not managed
			url = "";
		}
		System.out.println("[AUTH-SSO] >>>>>>>>>>>>>Started SSO flow<<<<<<<<<<<<<<<<<<<<");
		return url;
	}
	
	@Override
	public String handleAuthenticationRequest(HttpServletRequest request) throws OAuthConsumerException {
	
		String username = null;
		
		if(request.getParameterMap().containsKey("error") || request.getParameterMap().containsKey("denied")) {
		    throw new OAuthConsumerException("User cancel authentication");
		}
		String code = request.getParameter("code");
		String grant_type = "authorization_code";
		String state = request.getParameter("state");
	
		String issuer = null;
		String consumerKey = null;
		String consumerSecret = null;
		String accessTokenUri = null;
		String authenticationTokenUri = null;
		String accessToken = null;
	
		boolean requestParamStateValid = false;
		
		System.out.println("[AUTH-SSO] 1. RESPONSE OK, calling "+grant_type+" with code:"+code+" state:"+state);
		
		if(state.equals("mitreoid")) {
			requestParamStateValid = true;
			issuer = "mitreoid";
			consumerKey = mitreoidConsumerKey;
			consumerSecret = mitreoidConsumerSecret;
			accessTokenUri = mitreoidAccessTokenUri;
			authenticationTokenUri = mitreoidAuthenticationTokenUri;
	
			System.out.println("[AUTH-SSO] 2. MITREid BUILD call for 'access_token' to "+accessTokenUri+" with client_id:"+consumerKey+" client_secret:"+consumerSecret);
	
		} else if(state.equals("wso2is")) {
			requestParamStateValid = true;
			issuer = "wso2is";
			consumerKey = wso2isConsumerKey;
			consumerSecret = wso2isConsumerSecret;
			accessTokenUri = wso2isAccessTokenUri;
			authenticationTokenUri = wso2isAuthenticationTokenUri;
	
			System.out.println("[AUTH-SSO] 2. WSO2IS BUILD call for 'access_token' to "+accessTokenUri+" with client_id:"+consumerKey+" client_secret:"+consumerSecret);
	
		}
	
		if(requestParamStateValid) {
			try {
				System.out.println("[AUTH-SSO] 3. SEND POST for 'access_token'");
	
				HttpResponse responseToken = sendPostRequest(accessTokenUri, code, consumerKey, consumerSecret, grant_type);
				int statusCode = responseToken.getStatusLine().getStatusCode();
	
				System.out.println("[AUTH-SSO] 4. POST REPONSE CODE IS :" + statusCode);
	
				if(statusCode == HttpStatus.SC_OK) {
				HttpEntity entity = responseToken.getEntity();
	
				String content = EntityUtils.toString(entity);
				String authenticationTokenFullUri = null;
				String userInfo = null;
	
				if(issuer.equals("mitreoid")) {
					System.out.println("[AUTH-SSO] 5. Evaluate RESPONSE for MITREid");

					JSONObject json = new JSONObject(content);
					accessToken = json.getString("access_token");
					
					authenticationTokenFullUri = authenticationTokenUri + accessToken;
					userInfo = mitreOpenIdClaim;
					System.out.println("[AUTH-SSO] 6. MITREid 'access_token' is :"+accessToken);
	
				} else if(issuer.equals("wso2is")) {
					System.out.println("[AUTH-SSO] 5. Evaluate RESPONSE for WSO2IS");

					JSONObject json = new JSONObject(content);
					accessToken = json.getString("access_token");
					
					authenticationTokenFullUri = authenticationTokenUri; // accessToken is used as parameter for SendGET call
					userInfo = wso2OpenIdClaim;
					System.out.println("[AUTH-SSO] 6. WSO2IS 'access_token' is :"+accessToken);
	
				}
				System.out.println("[AUTH-SSO] 7. Request 'userinfo' to :"+authenticationTokenFullUri);
				HttpResponse responseUsername = issuer.equals("wso2is") ? sendGetRequest(authenticationTokenFullUri,accessToken) : sendGetRequest(authenticationTokenFullUri);
				String cont = EntityUtils.toString(responseUsername.getEntity()); 
				JSONObject jsonContent = new JSONObject(cont);
				System.out.println("[AUTH-SSO] 8. JSON Response is:"+jsonContent);
				String userWemail = jsonContent.getString(userInfo);
				String[] userparts = userWemail.split("@");
				System.out.println("[AUTH-SSO] 8.1 Response is:"+userparts[0]);
				username = userparts[0];
				}
			} catch (Exception e) {
				System.out.println("[AUTH-SSO] RESPONSE ERROR :" + e);
				throw new OAuthConsumerException("The exception occurred when tried communicate with identity provider service", e);
			}
		}
		return username;
	}
	
	/**
	* Send get request. (send access_token and get username)
	* @param authenticationTokenFullUri     with access token
	* @return                                  issuer's response.
	* @throws java.io.IOException
	*/
	private HttpResponse sendGetRequest(String authenticationTokenFullUri) throws IOException {
	HttpClient httpclient = HttpClients.createDefault();
	HttpGet httpget = new HttpGet(authenticationTokenFullUri);
	
	//Execute and return the response.
	return httpclient.execute(httpget);
	}
	
	private HttpResponse sendGetRequest(String authenticationTokenFullUri, String accessToken) throws IOException {
	HttpClient httpclient = HttpClients.createDefault();
	HttpGet httpget = new HttpGet(authenticationTokenFullUri);
		// for GET calls that require Auth Bearer in HTTP HEADERs e.g. WSO2 IdP add Auth header
		httpget.setHeader("Authorization","Bearer "+accessToken);
		System.out.println("[AUTH-SSO] 7.1. SEND modified HTTPGET for :"+authenticationTokenFullUri+ " with Auth Bearer:"+accessToken);
	//Execute and return the response.
	return httpclient.execute(httpget);
	}
	
	
	private HttpResponse sendPostRequest(String accessTokenUri, String code, String consumerKey,
	                                 String consumerSecret, String grantType) throws IOException {
	
	HttpClient httpclient = HttpClients.createDefault();
	HttpPost httppost = new HttpPost(accessTokenUri);
	httppost.setHeader("content-type","application/x-www-form-urlencoded; charset=utf-8");
	
	// Request parameters and other properties.
	List<NameValuePair> params = new ArrayList<NameValuePair>(4);
	params.add(new BasicNameValuePair("grant_type", grantType));
	params.add(new BasicNameValuePair("code", code));
	params.add(new BasicNameValuePair("redirect_uri", redirectUrl));
		params.add(new BasicNameValuePair("client_id", consumerKey));
	params.add(new BasicNameValuePair("client_secret", consumerSecret));
	httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		System.out.println("[AUTH-SSO] 3.1. SEND standard HTTPOST for grant :"+grantType);
	//Execute and return the response.
	return httpclient.execute(httppost);
	}
	
	/**
	* Convert string with params and values (like url) to map.
	* @param content   String like url params and values, joined by '&'.
	* @return          Map <name , value>
	*/
	private Map<String, String> responseContentToParamsMap(String content) {
	Map<String,String> responseParamsMap = new HashMap<String, String>();
	String contentParams[] = content.split("&");
	
	for (String contentParam : contentParams) {
	    String paramNameValue[] = contentParam.split("=");
	    responseParamsMap.put(paramNameValue[0], paramNameValue[1]);
	}
	
	return responseParamsMap;
	}
	
	/* added MITREid config param */
	public String getMitreoidConsumerKey() {
	return mitreoidConsumerKey;
	}
	
	public void setMitreoidConsumerKey(String mitreoidConsumerKey) {
	this.mitreoidConsumerKey = mitreoidConsumerKey;
	}
	
	public String getMitreoidConsumerSecret() {
	return mitreoidConsumerSecret;
	}
	
	public void setMitreoidConsumerSecret(String mitreoidConsumerSecret) {
	this.mitreoidConsumerSecret = mitreoidConsumerSecret;
	}
	
	public String getMitreoidTokenRequestUri(){
		return mitreoidTokenRequestUri;
	}
	
	public void setMitreoidTokenRequestUri(String mitreoidTokenRequestUri){
		this.mitreoidTokenRequestUri = mitreoidTokenRequestUri;
	}
	
	public void setMitreoidAccessTokenUri(String mitreoidAccessTokenUri){
		this.mitreoidAccessTokenUri = mitreoidAccessTokenUri;
	}
	public String getMitreoidAccessTokenUri(){
		return mitreoidAccessTokenUri;
	}
	
	public String getMitreoidAuthenticationTokenUri(){
		return mitreoidAuthenticationTokenUri;
	}
	
	public void setMitreoidAuthenticationTokenUri(String mitreoidAuthenticationTokenUri){
		this.mitreoidAuthenticationTokenUri = mitreoidAuthenticationTokenUri;
	}
	
	public String getMitreOpenIdClaim(){
		return mitreOpenIdClaim;
	}
	
	public void setMitreOpenIdClaim(String mitreOpenIdClaim){
		this.mitreOpenIdClaim = mitreOpenIdClaim;
	}
	
	/* added WSO2 IS config param */
	public String getWso2isConsumerKey() {
	return wso2isConsumerKey;
	}
	
	public void setWso2isConsumerKey(String wso2isConsumerKey) {
	this.wso2isConsumerKey = wso2isConsumerKey;
	}
	
	public String getWso2isConsumerSecret() {
	return wso2isConsumerSecret;
	}
	
	public void setWso2isConsumerSecret(String wso2isConsumerSecret) {
	this.wso2isConsumerSecret = wso2isConsumerSecret;
	}
	
	public String getWso2isTokenRequestUri(){
		return wso2isTokenRequestUri;
	}
	
	public void setWso2isTokenRequestUri(String wso2isTokenRequestUri){
		this.wso2isTokenRequestUri = wso2isTokenRequestUri;
	}
	
	public void setWso2isAccessTokenUri(String wso2isAccessTokenUri){
		this.wso2isAccessTokenUri = wso2isAccessTokenUri;
	}
	public String getWso2isAccessTokenUri(){
		return wso2isAccessTokenUri;
	}
	
	public String getWso2isAuthenticationTokenUri(){
		return wso2isAuthenticationTokenUri;
	}
	
	public void setWso2isAuthenticationTokenUri(String wso2isAuthenticationTokenUri){
		this.wso2isAuthenticationTokenUri = wso2isAuthenticationTokenUri;
	}
	
	public String getWso2OpenIdClaim(){
		return wso2OpenIdClaim;
	}
	
	public void setWso2OpenIdClaim(String wso2OpenIdClaim){
		this.wso2OpenIdClaim = wso2OpenIdClaim;
	}
	}
