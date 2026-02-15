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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.junit.jupiter.api.Test;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslManagerBundle;

/**
 * Tests for {@link ReloadableX509KeyManager}.
 *
 * @author Ujjawal Sharma
 */
class ReloadableX509KeyManagerTests {

	@Test
	void constructorExtractsKeyManagerFromBundle() {
		X509ExtendedKeyManager delegate = mock();
		SslBundle bundle = createBundleWithKeyManager(delegate);
		ReloadableX509KeyManager reloadable = new ReloadableX509KeyManager(bundle);
		String alias = "test-alias";
		given(delegate.getPrivateKey(alias)).willReturn(mock(PrivateKey.class));
		assertThat(reloadable.getPrivateKey(alias)).isNotNull();
	}

	@Test
	void constructorThrowsWhenNoX509ExtendedKeyManagerInBundle() {
		KeyManager nonX509KeyManager = mock(KeyManager.class);
		KeyManagerFactory kmf = mock(KeyManagerFactory.class);
		given(kmf.getKeyManagers()).willReturn(new KeyManager[] { nonX509KeyManager });
		SslManagerBundle managers = mock(SslManagerBundle.class);
		given(managers.getKeyManagerFactory()).willReturn(kmf);
		SslBundle bundle = mock(SslBundle.class);
		given(bundle.getManagers()).willReturn(managers);
		assertThatIllegalStateException().isThrownBy(() -> new ReloadableX509KeyManager(bundle))
			.withMessageContaining("No X509ExtendedKeyManager found");
	}

	@Test
	void updateKeyManagerSwapsDelegateForNewHandshakes() {
		X509ExtendedKeyManager firstDelegate = mock();
		X509ExtendedKeyManager secondDelegate = mock();
		SslBundle firstBundle = createBundleWithKeyManager(firstDelegate);
		SslBundle secondBundle = createBundleWithKeyManager(secondDelegate);

		String alias = "test";
		X509Certificate[] firstChain = new X509Certificate[] { mock(X509Certificate.class) };
		X509Certificate[] secondChain = new X509Certificate[] { mock(X509Certificate.class),
				mock(X509Certificate.class) };
		given(firstDelegate.getCertificateChain(alias)).willReturn(firstChain);
		given(secondDelegate.getCertificateChain(alias)).willReturn(secondChain);

		ReloadableX509KeyManager reloadable = new ReloadableX509KeyManager(firstBundle);
		assertThat(reloadable.getCertificateChain(alias)).hasSize(1);

		reloadable.updateKeyManager(secondBundle);
		assertThat(reloadable.getCertificateChain(alias)).hasSize(2);
	}

	@Test
	void delegatesChooseServerAlias() {
		X509ExtendedKeyManager delegate = mock();
		given(delegate.chooseServerAlias("RSA", null, null)).willReturn("server-alias");
		ReloadableX509KeyManager reloadable = new ReloadableX509KeyManager(createBundleWithKeyManager(delegate));
		assertThat(reloadable.chooseServerAlias("RSA", null, null)).isEqualTo("server-alias");
	}

	@Test
	void delegatesChooseEngineServerAlias() {
		X509ExtendedKeyManager delegate = mock();
		SSLEngine engine = mock(SSLEngine.class);
		given(delegate.chooseEngineServerAlias("RSA", null, engine)).willReturn("engine-alias");
		ReloadableX509KeyManager reloadable = new ReloadableX509KeyManager(createBundleWithKeyManager(delegate));
		assertThat(reloadable.chooseEngineServerAlias("RSA", null, engine)).isEqualTo("engine-alias");
	}

	@Test
	void delegatesGetClientAliases() {
		X509ExtendedKeyManager delegate = mock();
		Principal[] issuers = new Principal[] { mock(Principal.class) };
		given(delegate.getClientAliases("RSA", issuers)).willReturn(new String[] { "a", "b" });
		ReloadableX509KeyManager reloadable = new ReloadableX509KeyManager(createBundleWithKeyManager(delegate));
		assertThat(reloadable.getClientAliases("RSA", issuers)).containsExactly("a", "b");
	}

	@Test
	void delegatesGetServerAliases() {
		X509ExtendedKeyManager delegate = mock();
		given(delegate.getServerAliases("RSA", null)).willReturn(new String[] { "s1" });
		ReloadableX509KeyManager reloadable = new ReloadableX509KeyManager(createBundleWithKeyManager(delegate));
		assertThat(reloadable.getServerAliases("RSA", null)).containsExactly("s1");
	}

	private SslBundle createBundleWithKeyManager(X509ExtendedKeyManager keyManager) {
		KeyManagerFactory kmf = mock(KeyManagerFactory.class);
		given(kmf.getKeyManagers()).willReturn(new KeyManager[] { keyManager });
		SslManagerBundle managers = mock(SslManagerBundle.class);
		given(managers.getKeyManagerFactory()).willReturn(kmf);
		SslBundle bundle = mock(SslBundle.class);
		given(bundle.getManagers()).willReturn(managers);
		return bundle;
	}

}
