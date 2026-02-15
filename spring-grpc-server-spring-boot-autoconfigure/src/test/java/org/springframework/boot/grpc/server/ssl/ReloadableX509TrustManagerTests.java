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
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

import org.junit.jupiter.api.Test;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslManagerBundle;

/**
 * Tests for {@link ReloadableX509TrustManager}.
 *
 * @author Ujjawal Sharma
 */
class ReloadableX509TrustManagerTests {

	@Test
	void constructorExtractsTrustManagerFromBundle() {
		X509ExtendedTrustManager delegate = mock();
		X509Certificate[] issuers = new X509Certificate[] { mock(X509Certificate.class) };
		given(delegate.getAcceptedIssuers()).willReturn(issuers);
		ReloadableX509TrustManager reloadable = new ReloadableX509TrustManager(createBundleWithTrustManager(delegate));
		assertThat(reloadable.getAcceptedIssuers()).hasSize(1);
	}

	@Test
	void constructorThrowsWhenNoX509ExtendedTrustManagerInBundle() {
		TrustManager nonX509TrustManager = mock(TrustManager.class);
		TrustManagerFactory tmf = mock(TrustManagerFactory.class);
		given(tmf.getTrustManagers()).willReturn(new TrustManager[] { nonX509TrustManager });
		SslManagerBundle managers = mock(SslManagerBundle.class);
		given(managers.getTrustManagerFactory()).willReturn(tmf);
		SslBundle bundle = mock(SslBundle.class);
		given(bundle.getManagers()).willReturn(managers);
		assertThatIllegalStateException().isThrownBy(() -> new ReloadableX509TrustManager(bundle))
			.withMessageContaining("No X509ExtendedTrustManager found");
	}

	@Test
	void updateTrustManagerSwapsDelegateForNewHandshakes() throws CertificateException {
		X509ExtendedTrustManager firstDelegate = mock();
		X509ExtendedTrustManager secondDelegate = mock();

		X509Certificate[] chain = new X509Certificate[] { mock(X509Certificate.class) };
		SSLEngine engine = mock(SSLEngine.class);

		willThrow(new CertificateException("untrusted")).given(firstDelegate).checkServerTrusted(chain, "RSA", engine);

		ReloadableX509TrustManager reloadable = new ReloadableX509TrustManager(
				createBundleWithTrustManager(firstDelegate));

		// First delegate rejects the chain
		org.assertj.core.api.Assertions.assertThatThrownBy(() -> reloadable.checkServerTrusted(chain, "RSA", engine))
			.isInstanceOf(CertificateException.class)
			.hasMessageContaining("untrusted");

		// After update, second delegate accepts the chain
		reloadable.updateTrustManager(createBundleWithTrustManager(secondDelegate));
		assertThatNoException().isThrownBy(() -> reloadable.checkServerTrusted(chain, "RSA", engine));
	}

	@Test
	void delegatesGetAcceptedIssuers() {
		X509ExtendedTrustManager delegate = mock();
		X509Certificate cert = mock(X509Certificate.class);
		given(delegate.getAcceptedIssuers()).willReturn(new X509Certificate[] { cert });
		ReloadableX509TrustManager reloadable = new ReloadableX509TrustManager(createBundleWithTrustManager(delegate));
		assertThat(reloadable.getAcceptedIssuers()).containsExactly(cert);
	}

	@Test
	void delegatesCheckClientTrustedWithEngine() throws CertificateException {
		X509ExtendedTrustManager delegate = mock();
		X509Certificate[] chain = new X509Certificate[] { mock(X509Certificate.class) };
		SSLEngine engine = mock(SSLEngine.class);

		willThrow(new CertificateException("bad client")).given(delegate).checkClientTrusted(chain, "RSA", engine);

		ReloadableX509TrustManager reloadable = new ReloadableX509TrustManager(createBundleWithTrustManager(delegate));
		org.assertj.core.api.Assertions.assertThatThrownBy(() -> reloadable.checkClientTrusted(chain, "RSA", engine))
			.isInstanceOf(CertificateException.class)
			.hasMessageContaining("bad client");
	}

	private SslBundle createBundleWithTrustManager(X509ExtendedTrustManager trustManager) {
		TrustManagerFactory tmf = mock(TrustManagerFactory.class);
		given(tmf.getTrustManagers()).willReturn(new TrustManager[] { trustManager });
		SslManagerBundle managers = mock(SslManagerBundle.class);
		given(managers.getTrustManagerFactory()).willReturn(tmf);
		SslBundle bundle = mock(SslBundle.class);
		given(bundle.getManagers()).willReturn(managers);
		return bundle;
	}

}
