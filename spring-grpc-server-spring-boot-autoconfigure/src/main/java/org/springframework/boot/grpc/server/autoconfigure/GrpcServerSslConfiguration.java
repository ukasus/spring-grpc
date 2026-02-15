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

package org.springframework.boot.grpc.server.autoconfigure;

import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.grpc.server.ssl.ReloadableX509KeyManager;
import org.springframework.boot.grpc.server.ssl.ReloadableX509TrustManager;
import org.springframework.boot.ssl.NoSuchSslBundleException;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;

/**
 * {@link Configuration} for gRPC server SSL support with hot reloading. Activated
 * whenever a SSL bundle is configured via {@code spring.grpc.server.ssl.bundle}.
 * <p>
 * Creates reloadable {@link KeyManagerFactory} and {@link TrustManagerFactory} beans that
 * automatically pick up updated certificates when the underlying SSL bundle is refreshed.
 *
 * @author Ujjawal Sharma
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "spring.grpc.server.ssl", name = "bundle")
class GrpcServerSslConfiguration {

	private static final Log logger = LogFactory.getLog(GrpcServerSslConfiguration.class);

	@Bean
	ReloadableSslManagers reloadableSslManagers(GrpcServerProperties serverProperties, SslBundles sslBundles) {
		final var ssl = serverProperties.getSsl();
		final String bundleName = ssl.getBundle();
		Assert.notNull(bundleName, "SSL bundle name must not be null");
		SslBundle sslBundle = getSslBundle(sslBundles, bundleName);
		ReloadableX509KeyManager keyManager = new ReloadableX509KeyManager(sslBundle);
		@Nullable
		ReloadableX509TrustManager trustManager = ssl.isSecure() ? new ReloadableX509TrustManager(sslBundle) : null;
		sslBundles.addBundleUpdateHandler(bundleName, (bundle) -> {
			logger.info("Reloading ssl bundle: " + bundleName);
			keyManager.updateKeyManager(bundle);
			if (trustManager != null) {
				trustManager.updateTrustManager(bundle);
			}
		});
		return new ReloadableSslManagers(keyManager, trustManager);
	}

	@Bean
	KeyManagerFactory grpcKeyManagerFactory(ReloadableSslManagers sslManagers) {
		return new KeyManagerFactoryWrapper(sslManagers.keyManager());
	}

	@Bean
	@Nullable
	TrustManagerFactory grpcTrustManagerFactory(ReloadableSslManagers sslManagers) {
		if (sslManagers.trustManager() == null) {
			return null;
		}
		return new TrustManagerFactoryWrapper(sslManagers.trustManager());
	}

	private SslBundle getSslBundle(SslBundles sslBundles, String bundleName) {
		try {
			return sslBundles.getBundle(bundleName);
		}
		catch (NoSuchSslBundleException ex) {
			throw new IllegalStateException("SSL bundle '" + bundleName + "' not found.", ex);
		}
	}

	record ReloadableSslManagers(ReloadableX509KeyManager keyManager,
			@Nullable ReloadableX509TrustManager trustManager) {
	}

	private static final class KeyManagerFactoryWrapper extends KeyManagerFactory {

		private KeyManagerFactoryWrapper(X509ExtendedKeyManager keyManager) {
			super(new KeyManagerFactorySpiWrapper(keyManager), null, "reloadable");
		}

	}

	private static final class TrustManagerFactoryWrapper extends TrustManagerFactory {

		private TrustManagerFactoryWrapper(X509ExtendedTrustManager trustManager) {
			super(new TrustManagerFactorySpiWrapper(trustManager), null, "reloadable");
		}

	}

	private static final class KeyManagerFactorySpiWrapper extends KeyManagerFactorySpi {

		private final X509ExtendedKeyManager keyManager;

		private KeyManagerFactorySpiWrapper(X509ExtendedKeyManager keyManager) {
			this.keyManager = keyManager;
		}

		@Override
		protected void engineInit(KeyStore keyStore, char[] chars) {
			// Do nothing
		}

		@Override
		protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
			// Do nothing
		}

		@Override
		protected KeyManager[] engineGetKeyManagers() {
			return new KeyManager[] { this.keyManager };
		}

	}

	private static final class TrustManagerFactorySpiWrapper extends TrustManagerFactorySpi {

		private final X509ExtendedTrustManager trustManager;

		private TrustManagerFactorySpiWrapper(X509ExtendedTrustManager trustManager) {
			this.trustManager = trustManager;
		}

		@Override
		protected void engineInit(KeyStore keyStore) {
			// Do nothing
		}

		@Override
		protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
			// Do nothing
		}

		@Override
		protected TrustManager[] engineGetTrustManagers() {
			return new TrustManager[] { this.trustManager };
		}

	}

}
