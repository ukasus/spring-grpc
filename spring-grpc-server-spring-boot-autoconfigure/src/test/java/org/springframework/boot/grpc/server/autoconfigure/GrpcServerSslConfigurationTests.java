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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.grpc.server.ssl.ReloadableX509KeyManager;
import org.springframework.boot.grpc.server.ssl.ReloadableX509TrustManager;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.grpc.server.GrpcServerFactory;
import org.springframework.grpc.server.NettyGrpcServerFactory;
import org.springframework.grpc.server.ShadedNettyGrpcServerFactory;
import org.springframework.grpc.server.lifecycle.GrpcServerLifecycle;

import io.grpc.BindableService;
import io.grpc.ServerServiceDefinition;

/**
 * Tests for {@link GrpcServerSslConfiguration}.
 *
 * @author Ujjawal Sharma
 */
class GrpcServerSslConfigurationTests {

	private static final String SSL_PROPERTIES = "spring.grpc.server.ssl.bundle=ssltest";

	private static final String KEYSTORE_LOCATION = "spring.ssl.bundle.jks.ssltest.keystore.location=classpath:org/springframework/boot/grpc/server/autoconfigure/test.jks";

	private static final String KEYSTORE_PASSWORD = "spring.ssl.bundle.jks.ssltest.keystore.password=secret";

	private static final String KEY_PASSWORD = "spring.ssl.bundle.jks.ssltest.key.password=password";

	private final BindableService service = mock();

	private final ServerServiceDefinition serviceDefinition = ServerServiceDefinition.builder("my-service").build();

	@BeforeEach
	void prepareForTest() {
		given(this.service.bindService()).willReturn(this.serviceDefinition);
	}

	private ApplicationContextRunner contextRunner() {
		return new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(GrpcServerAutoConfiguration.class,
					GrpcServerFactoryAutoConfiguration.class, SslAutoConfiguration.class))
			.withBean("shadedNettyGrpcServerLifecycle", GrpcServerLifecycle.class, Mockito::mock)
			.withBean("nettyGrpcServerLifecycle", GrpcServerLifecycle.class, Mockito::mock)
			.withBean("inProcessGrpcServerLifecycle", GrpcServerLifecycle.class, Mockito::mock)
			.withBean(BindableService.class, () -> this.service);
	}

	@Test
	void whenSslBundleConfiguredThenReloadableManagersAreCreated() {
		this.contextRunner()
			.withPropertyValues(SSL_PROPERTIES, KEYSTORE_LOCATION, KEYSTORE_PASSWORD, KEY_PASSWORD,
					"spring.grpc.server.port=0")
			.run((context) -> {
				assertThat(context).hasSingleBean(GrpcServerSslConfiguration.ReloadableSslManagers.class);
				assertThat(context).hasBean("grpcKeyManagerFactory");
				assertThat(context).getBean("grpcKeyManagerFactory").isInstanceOf(KeyManagerFactory.class);
			});
	}

	@Test
	void whenSslBundleConfiguredThenKeyManagerFactoryIsReloadable() {
		this.contextRunner()
			.withPropertyValues(SSL_PROPERTIES, KEYSTORE_LOCATION, KEYSTORE_PASSWORD, KEY_PASSWORD,
					"spring.grpc.server.port=0")
			.run((context) -> {
				KeyManagerFactory kmf = context.getBean("grpcKeyManagerFactory", KeyManagerFactory.class);
				assertThat(kmf.getKeyManagers()).hasSize(1);
				assertThat(kmf.getKeyManagers()[0]).isInstanceOf(ReloadableX509KeyManager.class);
			});
	}

	@Test
	void whenSslBundleConfiguredWithSecureTrueThenTrustManagerFactoryIsReloadable() {
		this.contextRunner()
			.withPropertyValues(SSL_PROPERTIES, KEYSTORE_LOCATION, KEYSTORE_PASSWORD, KEY_PASSWORD,
					"spring.grpc.server.port=0")
			.run((context) -> {
				assertThat(context).hasBean("grpcTrustManagerFactory");
				TrustManagerFactory tmf = context.getBean("grpcTrustManagerFactory", TrustManagerFactory.class);
				assertThat(tmf.getTrustManagers()).hasSize(1);
				assertThat(tmf.getTrustManagers()[0]).isInstanceOf(ReloadableX509TrustManager.class);
			});
	}

	@Test
	void whenSslBundleConfiguredWithSecureFalseThenNoTrustManagerFactory() {
		this.contextRunner()
			.withPropertyValues(SSL_PROPERTIES, KEYSTORE_LOCATION, KEYSTORE_PASSWORD, KEY_PASSWORD,
					"spring.grpc.server.port=0", "spring.grpc.server.ssl.secure=false")
			.run((context) -> {
				assertThat(context).hasSingleBean(GrpcServerSslConfiguration.ReloadableSslManagers.class);
				GrpcServerSslConfiguration.ReloadableSslManagers managers = context
					.getBean(GrpcServerSslConfiguration.ReloadableSslManagers.class);
				assertThat(managers.keyManager()).isNotNull();
				assertThat(managers.trustManager()).isNull();
			});
	}

	@Test
	void whenNoSslBundleConfiguredThenNoReloadableManagers() {
		this.contextRunner().withPropertyValues("spring.grpc.server.port=0").run((context) -> {
			assertThat(context).doesNotHaveBean(GrpcServerSslConfiguration.ReloadableSslManagers.class);
			assertThat(context).doesNotHaveBean("grpcKeyManagerFactory");
			assertThat(context).doesNotHaveBean("grpcTrustManagerFactory");
		});
	}

	@Test
	void shadedNettyServerFactoryConsumesReloadableKeyManager() {
		this.contextRunner()
			.withPropertyValues(SSL_PROPERTIES, KEYSTORE_LOCATION, KEYSTORE_PASSWORD, KEY_PASSWORD,
					"spring.grpc.server.port=0")
			.run((context) -> {
				assertThat(context).getBean(GrpcServerFactory.class)
					.isInstanceOf(ShadedNettyGrpcServerFactory.class)
					.hasFieldOrProperty("keyManager");
				ShadedNettyGrpcServerFactory factory = context.getBean(ShadedNettyGrpcServerFactory.class);
				assertThat(factory).extracting("keyManager").isNotNull();
			});
	}

	@Test
	void nettyServerFactoryConsumesReloadableKeyManager() {
		this.contextRunner()
			.withPropertyValues(SSL_PROPERTIES, KEYSTORE_LOCATION, KEYSTORE_PASSWORD, KEY_PASSWORD,
					"spring.grpc.server.port=0")
			.withClassLoader(new FilteredClassLoader(io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder.class))
			.run((context) -> {
				assertThat(context).getBean(GrpcServerFactory.class)
					.isInstanceOf(NettyGrpcServerFactory.class)
					.hasFieldOrProperty("keyManager");
				NettyGrpcServerFactory factory = context.getBean(NettyGrpcServerFactory.class);
				assertThat(factory).extracting("keyManager").isNotNull();
			});
	}

}
