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
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.springframework.boot.ssl.SslBundle;

/**
 * A {@link X509ExtendedKeyManager} that can be reloaded with new key material at runtime.
 * Uses a volatile delegate pattern so that new TLS handshakes immediately pick up updated
 * credentials without requiring a server restart.
 *
 * @author Ujjawal Sharma
 */
public final class ReloadableX509KeyManager extends X509ExtendedKeyManager {

	private volatile X509ExtendedKeyManager delegate;

	/**
	 * Creates a new {@link ReloadableX509KeyManager} initialized with key material from
	 * the given SSL bundle.
	 * @param sslBundle the initial SSL bundle
	 */
	public ReloadableX509KeyManager(SslBundle sslBundle) {
		this.delegate = extractKeyManager(sslBundle);
	}

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		return this.delegate.getClientAliases(keyType, issuers);
	}

	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		return this.delegate.chooseClientAlias(keyType, issuers, socket);
	}

	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return this.delegate.getServerAliases(keyType, issuers);
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		return this.delegate.chooseServerAlias(keyType, issuers, socket);
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		return this.delegate.getCertificateChain(alias);
	}

	@Override
	public PrivateKey getPrivateKey(String alias) {
		return this.delegate.getPrivateKey(alias);
	}

	@Override
	public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
		return this.delegate.chooseEngineClientAlias(keyType, issuers, engine);
	}

	@Override
	public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
		return this.delegate.chooseEngineServerAlias(keyType, issuers, engine);
	}

	/**
	 * Updates the key manager with the latest key material from the SSL bundle.
	 * @param sslBundle the SSL bundle
	 */
	public void updateKeyManager(SslBundle sslBundle) {
		this.delegate = extractKeyManager(sslBundle);
	}

	private static X509ExtendedKeyManager extractKeyManager(SslBundle sslBundle) {
		KeyManagerFactory kmf = sslBundle.getManagers().getKeyManagerFactory();
		for (KeyManager km : kmf.getKeyManagers()) {
			if (km instanceof X509ExtendedKeyManager xkm) {
				return xkm;
			}
		}
		throw new IllegalStateException("No X509ExtendedKeyManager found in SSL bundle");
	}

}
