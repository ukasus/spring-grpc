/*
 * Copyright 2012-present the original author or authors.
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.jspecify.annotations.Nullable;

import org.springframework.boot.grpc.server.ssl.ReloadableX509KeyManager;
import org.springframework.boot.grpc.server.ssl.ReloadableX509TrustManager;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.util.Assert;

/**
 * Resolves SSL managers for gRPC server factories.
 *
 * @author Ujjawal Sharma
 */
final class GrpcServerSslManagerResolver {

	private GrpcServerSslManagerResolver() {
	}

	static ResolvedSslManagers resolve(GrpcServerProperties properties, SslBundles bundles,
			TrustManagerFactory insecureTrustManager) {
		if (!properties.getSsl().determineEnabled()) {
			return new ResolvedSslManagers(null, null);
		}
		String bundleName = properties.getSsl().getBundle();
		Assert.notNull(bundleName, () -> "SSL bundleName must not be null");
		SslBundle bundle = bundles.getBundle(bundleName);

		KeyManagersResolution keyManagers = resolveKeyManagers(bundle);
		TrustManagersResolution trustManagers = resolveTrustManagers(properties, bundle, insecureTrustManager);

		registerBundleUpdateHandler(bundles, bundleName, keyManagers.reloadableManager(),
				trustManagers.reloadableManager());
		return new ResolvedSslManagers(keyManagers.keyManagers(), trustManagers.trustManagers());
	}

	private static KeyManagersResolution resolveKeyManagers(SslBundle bundle) {
		ReloadableX509KeyManager reloadableManager = new ReloadableX509KeyManager(bundle);
		return new KeyManagersResolution(new KeyManager[] { reloadableManager }, reloadableManager);
	}

	private static TrustManagersResolution resolveTrustManagers(GrpcServerProperties properties, SslBundle bundle,
			TrustManagerFactory insecureTrustManager) {
		if (!properties.getSsl().isSecure()) {
			return new TrustManagersResolution(insecureTrustManager.getTrustManagers(), null);
		}
		ReloadableX509TrustManager reloadableManager = new ReloadableX509TrustManager(bundle);
		return new TrustManagersResolution(new TrustManager[] { reloadableManager }, reloadableManager);
	}

	private static void registerBundleUpdateHandler(SslBundles bundles, String bundleName,
			@Nullable ReloadableX509KeyManager keyManager, @Nullable ReloadableX509TrustManager trustManager) {
		if (keyManager == null && trustManager == null) {
			return;
		}
		bundles.addBundleUpdateHandler(bundleName, updatedBundle -> {
			if (keyManager != null) {
				keyManager.updateKeyManager(updatedBundle);
			}
			if (trustManager != null) {
				trustManager.updateTrustManager(updatedBundle);
			}
		});
	}

	record ResolvedSslManagers(KeyManager @Nullable [] keyManagers, TrustManager @Nullable [] trustManagers) {
	}

	private record KeyManagersResolution(KeyManager[] keyManagers,
			@Nullable ReloadableX509KeyManager reloadableManager) {
	}

	private record TrustManagersResolution(TrustManager[] trustManagers,
			@Nullable ReloadableX509TrustManager reloadableManager) {
	}

}
