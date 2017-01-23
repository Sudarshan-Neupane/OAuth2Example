import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.json.simple.parser.JSONParser;

public class RakutenTest {

	public static final String ACCESS_TOKEN = "access_token";
	public static final String CLIENT_ID = "client_id";
	public static final String CLIENT_SECRET = "client_secret";
	public static final String REFRESH_TOKEN = "refresh_token";
	public static final String USERNAME = "username";
	public static final String PASSWORD = "password";
	public static final String CODE = "code";
	public static final String CALLER = "caller";
	public static final String AUTHENTICATION_SERVER_URL = "authentication_server_url";
	public static final String REDIRECT_URI = "redirect_uri";
	public static final String RESOURCE_SERVER_URL = "resource_server_url";
	public static final String RESPONSE_TYPE = "response_type";
	public static final String GRANT_TYPE_PASSWORD = "password";
	public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
	public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
	public static final String SCOPE = "scope";
	public static final String AUTHORIZATION = "Authorization";
	public static final String BEARER = "Bearer";
	public static final String BASIC = "Basic";
	public static final String JSON_CONTENT = "application/json";
	public static final String XML_CONTENT = "application/xml";
	public static final String URL_ENCODED_CONTENT = "application/x-www-form-urlencoded";

	public static final int HTTP_OK = 200;
	public static final int HTTP_FORBIDDEN = 403;
	public static final int HTTP_UNAUTHORIZED = 401;
	public static String proxyHost = System.getProperty("https.proxyHost");
	public static String proxyPort = System.getProperty("https.proxyPort");

	public static void main(String[] args) throws Exception {

		// Load the properties file
		Properties config = getClientConfigProps();
		createOAuthDetails(config);

		// Validate Input
		if (!isValidInput()) {
			System.out.println("Please provide valid config properties to continue.");
			System.exit(0);
		}

		// Determine operation
		if (isAccessTokenRequest()) {
			// Generate new Access token
			String urlString = getAuthorizationURL();
			System.out.println("URL string :- " + urlString);

			System.out.println("Enter the Authorization code:");
			Scanner in = new Scanner(System.in);
			// for authorization code form url
			String authorizationCode = in.next();
			String accessToken1 = getAccessToken(authorizationCode);

			if (isValid(accessToken1)) {
				getProtectedResource(accessToken1);
			} else {
				System.out.println("Could not generate Access token for client_credentials grant_type");
			}
		}

		else {
			// Access protected resource from server using OAuth2.0
			// Response from the resource server must be in Json or Urlencoded
			// or xml
			System.out.println("Resource endpoint url: " + getResourceServerUrl());
			System.out.println("Attempting to retrieve protected resource");
			getProtectedResource("test");
		}
	}

	// Get order data
	public static void getProtectedResource(String accessToken) {
		System.out.println("####################  GET  ORDER ####################");
		String resourceURL = "https://api.rakuten.com/Marketplace/orderservices/";
		String token = "e52c45f561134cff8b1e7b84413ff472";
		String secret = "701756fdba7f48b8b846a5dd8d0cc3ee";
		HttpPost get = new HttpPost(resourceURL);
		get.addHeader(AUTHORIZATION, getAuthorizationHeaderForAccessToken(accessToken));
		get.addHeader("Accept", "application/json");
		get.addHeader("Content-Type", "application/json");

		CredentialsProvider credsProvider = new BasicCredentialsProvider();
		credsProvider.setCredentials(new AuthScope("api.rakuten.com", 443), new UsernamePasswordCredentials(token, secret));
		CloseableHttpClient client = HttpClients.custom().setDefaultCredentialsProvider(credsProvider).build();

		// DefaultHttpClient client = new DefaultHttpClient();
		String proxyHost = System.getProperty("https.proxyHost");
		String proxyPort = System.getProperty("https.proxyPort");
		HttpHost proxy = new HttpHost(proxyHost, Integer.valueOf(proxyPort), "http");
		RequestConfig config = RequestConfig.custom().setConnectTimeout(50000).setConnectionRequestTimeout(50000).setProxy(proxy)
				.setAuthenticationEnabled(true).build();
		get.setConfig(config);
		HttpResponse response = null;
		int code = -1;
		try {
			// get.setEntity(
			// new StringEntity(
			// "{\"__type\":\"GetOrder\",\"OrderIdentifier\":{\"Type\":1,\"Value\":\"Sample
			// Value\"}}",
			// ContentType.create("application/json")
			// ));
			String jsonString = "{\"__type\":\"GetOrder\",\"OrderIdentifier\":{\"Type\":1,\"Value\":\"Sample Value\"}}";
			get.setEntity(new StringEntity(jsonString, ContentType.create("application/json")));
			System.out.println(" JSON " + jsonString);
			// get.setEntity(
			// new StringEntity(
			// "{\" __type\":\"GetOrder\"}",
			// ContentType.create("application/json")
			// ));
			response = client.execute(get);
			code = response.getStatusLine().getStatusCode();
			if (code == 401 || code == 403) {
				// Access token is invalid or expired.Regenerate the access
				// token
				System.out.println("Access token is invalid or expired. Regenerating access token....");
				if (isValid(accessToken)) {
					// update the access token
					// System.out.println("New access token: " + accessToken);
					setAccessToken(accessToken);
					get.removeHeaders(AUTHORIZATION);
					get.addHeader(AUTHORIZATION, getAuthorizationHeaderForAccessToken(accessToken));
					get.releaseConnection();
					response = client.execute(get);
					code = response.getStatusLine().getStatusCode();
					if (code >= 400) {
						throw new RuntimeException("Could not access protected resource. Server returned http code: " + code);

					}

				} else {
					throw new RuntimeException("Could not regenerate access token");
				}

			}
			System.out.println(response.toString());
			System.out.println("==================================================================");

			handleResponse(response);

		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			get.releaseConnection();
		}

	}

	public static String getAccessToken(String authCode) {
		System.out.println("################### ACCESS TOKEN RESPONSE  #################");
		HttpPost post = new HttpPost("https://api.rakuten.com/Authorization/Token");
		post.addHeader("accept", "application/json");
		String clientId = getClientId();
		String clientSecret = getClientSecret();

		HttpParams my_httpParams = new BasicHttpParams();
		HttpConnectionParams.setConnectionTimeout(my_httpParams, 300000);
		HttpConnectionParams.setSoTimeout(my_httpParams, 30000);

		List<BasicNameValuePair> parametersBody = new ArrayList<BasicNameValuePair>();

		parametersBody.add(new BasicNameValuePair(CLIENT_ID, clientId));
		parametersBody.add(new BasicNameValuePair("grant_type", "authorization_code"));

		parametersBody.add(new BasicNameValuePair(CLIENT_SECRET, clientSecret));

		if (isValid(authCode)) {
			parametersBody.add(new BasicNameValuePair(CODE, authCode));
		}
		String proxyHost = System.getProperty("https.proxyHost");
		String proxyPort = System.getProperty("https.proxyPort");
		HttpHost proxy = new HttpHost(proxyHost, Integer.valueOf(proxyPort), "http");

		DefaultHttpClient client = new DefaultHttpClient(my_httpParams);
		client.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
		HttpResponse response = null;
		String accessToken = null;
		try {
			post.setEntity(new UrlEncodedFormEntity(parametersBody, HTTP.UTF_8));

			response = client.execute(post);
			int statusCode = response.getStatusLine().getStatusCode();

			System.out.println("Response Code: " + statusCode + "  message: " + response.getStatusLine().getReasonPhrase());

			if (statusCode == HTTP_UNAUTHORIZED) {
				System.out.println("Authorization server expects Basic authentication");
				// Add Basic Authorization header
				post.addHeader(AUTHORIZATION, getBasicAuthorizationHeader(getClientId(), getClientSecret()));
				System.out.println("Retry with client credentials");
				post.releaseConnection();
				response = client.execute(post);
				statusCode = response.getStatusLine().getStatusCode();
				if (statusCode == 401 || statusCode == 403) {
					System.out.println("Could not authenticate using client credentials.");
					throw new RuntimeException("Could not retrieve access token for client: " + getClientId());

				}

			}
			Map<String, String> map = handleResponse(response);
			accessToken = map.get(ACCESS_TOKEN);
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return accessToken;

	}

	public static String getBasicAuthorizationHeader(String username, String password) {
		return BASIC + " " + encodeCredentials(username, password);
	}

	public static String encodeCredentials(String username, String password) {
		String cred = username + ":" + password;
		String encodedValue = null;
		byte[] encodedBytes = Base64.encodeBase64(cred.getBytes());
		encodedValue = new String(encodedBytes);
		System.out.println("encodedBytes " + new String(encodedBytes));

		byte[] decodedBytes = Base64.decodeBase64(encodedBytes);
		System.out.println("decodedBytes " + new String(decodedBytes));

		return encodedValue;

	}

	// For url
	public static String getAuthorizationURL() throws Exception {
		String redirectURI = getRedirectURI();
		String encodedRedirectURI = URLEncoder.encode(redirectURI, "UTF-8");
		StringBuilder urlRequest = new StringBuilder();

		urlRequest.append(getAuthenticationServerUrl());

		urlRequest.append("client_id=").append(clientId);
		urlRequest.append("&redirect_uri=").append(encodedRedirectURI);
		urlRequest.append("&scope=").append(scope);
		urlRequest.append("&response_type=").append("code");
		urlRequest.append("&state=").append(UUID.randomUUID().toString());
		String urlString = urlRequest.toString();
		return urlString;

	}

	// property file
	public static Properties getClientConfigProps() {
		Properties props = new Properties();
		try {
			File file = new File("/wbso/user/home/hhq2vmy/tmp/rakuten/testOauth/Oauth2Client.config");

			FileInputStream fileInput = new FileInputStream(file);
			props.load(fileInput);
		}

		catch (IOException e) {
			System.out.println("Could not load properties");
			e.printStackTrace();
			return null;
		}

		return props;
	}

	// set the oAuth details
	public static void createOAuthDetails(Properties config) {
		setAccessToken((String) config.get(ACCESS_TOKEN));
		setRefreshToken((String) config.get(REFRESH_TOKEN));
		setResponseType((String) config.get(RESPONSE_TYPE));
		setClientId((String) config.get(CLIENT_ID));
		setClientSecret((String) config.get(CLIENT_SECRET));
		setScope((String) config.get(SCOPE));
		setAuthenticationServerUrl((String) config.get(AUTHENTICATION_SERVER_URL));
		setRedirectURI((String) config.get(REDIRECT_URI));
		setUsername((String) config.get(USERNAME));
		setPassword((String) config.get(PASSWORD));
		setResourceServerUrl((String) config.get(RESOURCE_SERVER_URL));
		if (!isValid(getResourceServerUrl())) {
			System.out.println("Resource server url is null. Will assume request is for generating Access token");
			setAccessTokenRequest(true);
		}

	}

	public static boolean isValidInput() {

		String grantType = getResponseType();

		if (!isValid(grantType)) {
			System.out.println("Please provide valid value for grant_type");
			return false;
		}

		if (!isValid(getAuthenticationServerUrl())) {
			System.out.println("Please provide valid value for authentication server url");
			return false;
		}

		if (grantType.equals(GRANT_TYPE_PASSWORD)) {
			if (!isValid(getUsername()) || !isValid(getPassword())) {
				System.out.println("Please provide valid username and password for password grant_type");
				return false;
			}
		}

		if (grantType.equals(GRANT_TYPE_CLIENT_CREDENTIALS)) {
			if (!isValid(getClientId()) || !isValid(getClientSecret())) {
				System.out.println("Please provide valid client_id and client_secret for client_credentials grant_type");
				return false;
			}
		}

		System.out.println("Validated Input");
		return true;

	}

	public static String getAuthorizationHeaderForAccessToken(String accessToken) {
		return BEARER + " " + accessToken;
	}

	public static boolean isValid(String str) {
		return (str != null && str.trim().length() > 0);
	}

	public static Map handleResponse(HttpResponse response) {
		String contentType = JSON_CONTENT;
		if (response.getEntity().getContentType() != null) {
			contentType = response.getEntity().getContentType().getValue();
		}
		if (contentType.contains(JSON_CONTENT)) {
			return handleJsonResponse(response);
		}
		// else if (contentType.contains(URL_ENCODED_CONTENT)) {
		// return handleURLEncodedResponse(response);
		// } else if (contentType.contains(XML_CONTENT)) {
		// return handleXMLResponse(response);
		// }
		else {
			// Unsupported Content type
			throw new RuntimeException("Cannot handle " + contentType
					+ " content type. Supported content types include JSON, XML and URLEncoded");
		}

	}

	public static Map handleJsonResponse(HttpResponse response) {
		Map<String, String> oauthLoginResponse = null;
		String contentType = response.getEntity().getContentType().getValue();
		try {
			oauthLoginResponse = (Map<String, String>) new JSONParser().parse(EntityUtils.toString(response.getEntity()));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		} catch (RuntimeException e) {
			System.out.println("Could not parse JSON response");
			throw e;
		}
		System.out.println();
		for (Map.Entry<String, String> entry : oauthLoginResponse.entrySet()) {
			System.out.println(String.format("  %s ====> %s", entry.getKey(), entry.getValue()));
			System.out.println("---------------------------------------------------------------");
		}
		return oauthLoginResponse;
	}

	private static String scope;
	private static String responseType;
	private static String clientId;
	private static String clientSecret;
	private static String accessToken;
	private static String refreshToken;
	private static String username;
	private static String password;
	private static String authenticationServerUrl;
	private static String resourceServerUrl;
	private static String redirectURI;
	private static boolean isAccessTokenRequest;

	public static String getScope() {
		return scope;
	}

	public static void setScope(String scope) {
		RakutenTest.scope = scope;
	}

	public static String getResponseType() {
		return responseType;
	}

	public static void setResponseType(String responseType) {
		RakutenTest.responseType = responseType;
	}

	public static String getClientId() {
		return clientId;
	}

	public static void setClientId(String clientId) {
		RakutenTest.clientId = clientId;
	}

	public static String getClientSecret() {
		return clientSecret;
	}

	public static void setClientSecret(String clientSecret) {
		RakutenTest.clientSecret = clientSecret;
	}

	public static String getAccessToken() {
		return accessToken;
	}

	public static void setAccessToken(String accessToken) {
		RakutenTest.accessToken = accessToken;
	}

	public static String getRefreshToken() {
		return refreshToken;
	}

	public static void setRefreshToken(String refreshToken) {
		RakutenTest.refreshToken = refreshToken;
	}

	public static String getAuthenticationServerUrl() {
		return authenticationServerUrl;
	}

	public static void setAuthenticationServerUrl(String authenticationServerUrl) {
		RakutenTest.authenticationServerUrl = authenticationServerUrl;
	}

	public static String getUsername() {
		return username;
	}

	public static void setUsername(String username) {
		RakutenTest.username = username;
	}

	public static String getPassword() {
		return password;
	}

	public static void setPassword(String password) {
		RakutenTest.password = password;
	}

	public static boolean isAccessTokenRequest() {
		return isAccessTokenRequest;
	}

	public static void setAccessTokenRequest(boolean isAccessTokenRequest) {
		RakutenTest.isAccessTokenRequest = isAccessTokenRequest;
	}

	public static String getRedirectURI() {
		return redirectURI;
	}

	public static void setRedirectURI(String redirectURI) {
		RakutenTest.redirectURI = redirectURI;
	}

	public static String getResourceServerUrl() {
		return resourceServerUrl;
	}

	public static void setResourceServerUrl(String resourceServerUrl) {
		RakutenTest.resourceServerUrl = resourceServerUrl;
	}

}
