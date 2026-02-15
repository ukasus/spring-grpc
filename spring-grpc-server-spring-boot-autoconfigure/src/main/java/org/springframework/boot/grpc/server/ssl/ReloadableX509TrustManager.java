/*
 * Copyright 2024-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.grpc.server.ssl;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

import org.springframework.boot.ssl.SslBundle;

/**
 * A {@link X509ExtendedTrustManager} that can be reloaded with new trust material at
 * runtime. Uses a volatile delegate pattern so that new TLS handshakes immediately pick
 * up updated trust material without requiring a server restart.
 *
 * @author Ujjawal Sharma
 */
public final class ReloadableX509TrustManager extends X509ExtendedTrustManager {

	private volatile X509ExtendedTrustManager delegate;

	/**
	 * Creates a new {@link ReloadableX509TrustManager} initialized with trust material
	 * from the given SSL bundle.
	 * @param sslBundle the initial SSL bundle
	 */
	public ReloadableX509TrustManager(SslBundle sslBundle) {
		this.delegate = extractTrustManager(sslBundle);
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException {
		this.delegate.checkClientTrusted(chain, authType, socket);
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException {
		this.delegate.checkClientTrusted(chain, authType, engine);
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		this.delegate.checkClientTrusted(chain, authType);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException {
		this.delegate.checkServerTrusted(chain, authType, socket);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException {
		this.delegate.checkServerTrusted(chain, authType, engine);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		this.delegate.checkServerTrusted(chain, authType);
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return this.delegate.getAcceptedIssuers();
	}

	/**
	 * Updates the trust manager with the latest trust material from the SSL bundle.
	 * @param sslBundle the SSL bundle
	 */
	public void updateTrustManager(SslBundle sslBundle) {
		this.delegate = extractTrustManager(sslBundle);
	}

	private static X509ExtendedTrustManager extractTrustManager(SslBundle sslBundle) {
		TrustManagerFactory tmf = sslBundle.getManagers().getTrustManagerFactory();
		for (TrustManager tm : tmf.getTrustManagers()) {
			if (tm instanceof X509ExtendedTrustManager xtm) {
				return xtm;
			}
		}
		throw new IllegalStateException("No X509ExtendedTrustManager found in SSL bundle");
	}

}
