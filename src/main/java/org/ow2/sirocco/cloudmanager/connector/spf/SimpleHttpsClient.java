package org.ow2.sirocco.cloudmanager.connector.spf;

import java.io.IOException;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;

import com.msopentech.odatajclient.engine.client.http.HttpClientFactory;
import com.msopentech.odatajclient.engine.client.http.HttpMethod;

class SimpleHttpsClient {

	private SimpleHttpsClientFactory factory;
	private String login;
	private String password;
	
	public SimpleHttpsClient(String login, String password)
	{
		this.login = login;
		this.password = password;
		this.factory = new SimpleHttpsClientFactory();
	}
	
	public SimpleHttpsClientFactory getFactory()
	{
		return factory;
	}
	
	/**
	 * Class used to instantiate HttpClient
	 */
	protected class SimpleHttpsClientFactory implements HttpClientFactory {

		public HttpClient createHttpClient(final HttpMethod method, final URI uri) {
			SSLContext sslContext = null;
			try {
				sslContext = SSLContext.getInstance("SSL");

				sslContext.init(null, new TrustManager[] { new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						return new X509Certificate[] {};
					}

					public void checkClientTrusted(X509Certificate[] certs, String authType) {
					}

					public void checkServerTrusted(X509Certificate[] certs, String authType) {
					}
				} }, new SecureRandom());

				SSLSocketFactory sf = new SSLSocketFactory(sslContext,
						SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

				Scheme httpsScheme = new Scheme("https", 443, sf);
				SchemeRegistry schemeRegistry = new SchemeRegistry();
				schemeRegistry.register(httpsScheme);

				BasicClientConnectionManager cm = new BasicClientConnectionManager(
						schemeRegistry);

				DefaultHttpClient httpclient = new DefaultHttpClient(cm);

				httpclient.getCredentialsProvider().setCredentials(
						AuthScope.ANY,
						new UsernamePasswordCredentials(login, password));
				httpclient.addRequestInterceptor(new PreemptiveAuthInterceptor(), 0);
				return httpclient;

			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}

	}

	/**
	 * Class used to process HTTP request
	 */
	 private static class PreemptiveAuthInterceptor implements HttpRequestInterceptor {

		public void process(final HttpRequest request, final HttpContext context)
				throws HttpException, IOException {
			AuthState authState = (AuthState) context
					.getAttribute(ClientContext.TARGET_AUTH_STATE);

			// If no auth scheme availalble yet, try to initialize it
			// preemptively
			if (authState.getAuthScheme() == null) {
				CredentialsProvider credsProvider = (CredentialsProvider) context
						.getAttribute(ClientContext.CREDS_PROVIDER);
				HttpHost targetHost = (HttpHost) context
						.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
				Credentials creds = credsProvider.getCredentials(new AuthScope(targetHost
						.getHostName(), targetHost.getPort()));
				if (creds == null)
					throw new HttpException("No credentials for preemptive authentication");
				authState.update(new BasicScheme(), creds);
			}
		}

	}
	 
	 
	 
}
