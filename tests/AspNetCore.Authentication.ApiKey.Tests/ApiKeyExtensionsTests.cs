// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.DependencyInjection;
	using Xunit;

	public class ApiKeyExtensionsTests
	{
		private Task<AuthenticationScheme> GetSchemeAsync(Action<AuthenticationBuilder> authenticationBuilderAction, string schemeName = ApiKeyDefaults.AuthenticationScheme)
		{
			ServiceCollection services = new ServiceCollection();
			authenticationBuilderAction(services.AddAuthentication());
			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			return schemeProvider.GetSchemeAsync(schemeName);
		}

		private class MockApiKeyAuthenticationService : IApiKeyAuthenticationService
		{
			public Task<IApiKey> AuthenticateAsync(string key)
			{
				throw new NotImplementedException();
			}
		}

		private class MockApiKeyProvider2 : IApiKeyAuthenticationService
		{
			public Task<IApiKey> AuthenticateAsync(string key)
			{
				throw new NotImplementedException();
			}
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_allows_chaining_default()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader());
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(string.Empty));
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInAuthorizationHeader()
				.AddApiKeyInAuthorizationHeader(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}


		[Fact]
		public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>());
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(string.Empty));
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>()
				.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
			services.AddAuthentication()
				.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>();

			IEnumerable<ServiceDescriptor> serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
			Assert.Equal(2, serviceDescriptors.Count());

			ServiceDescriptor serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
		}

		[Fact]
		public void AddApiKeyInAuthorizationHeader_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>();

			ServiceDescriptor serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			ServiceProvider sp = services.BuildServiceProvider();
			IApiKeyAuthenticationService provider = sp.GetService<IApiKeyAuthenticationService>();

			Assert.NotNull(provider);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
		}


		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInAuthorizationHeader_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInAuthorizationHeader(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInAuthorizationHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddApiKeyInHeader_allows_chaining_default()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader());
		}

		[Fact]
		public void AddApiKeyInHeader_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeader_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(string.Empty));
		}

		[Fact]
		public void AddApiKeyInHeader_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeader_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInHeader_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInHeader()
				.AddApiKeyInHeader(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}


		[Fact]
		public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>());
		}

		[Fact]
		public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(string.Empty));
		}

		[Fact]
		public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeader_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeader<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInHeader_TApiKeyProvider_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInHeader<MockApiKeyAuthenticationService>()
				.AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddApiKeyInHeader_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
			services.AddAuthentication()
				.AddApiKeyInHeader<MockApiKeyAuthenticationService>();

			IEnumerable<ServiceDescriptor> serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
			Assert.Equal(2, serviceDescriptors.Count());

			ServiceDescriptor serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
		}

		[Fact]
		public void AddApiKeyInHeader_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInHeader<MockApiKeyAuthenticationService>();

			ServiceDescriptor serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			ServiceProvider sp = services.BuildServiceProvider();
			IApiKeyAuthenticationService provider = sp.GetService<IApiKeyAuthenticationService>();

			Assert.NotNull(provider);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
		}


		[Fact]
		public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeader_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeader_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeader_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeader(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_allows_chaining_default()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams());
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(string.Empty));
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInHeaderOrQueryParams()
				.AddApiKeyInHeaderOrQueryParams(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}


		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>());
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(string.Empty));
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>()
				.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
			services.AddAuthentication()
				.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>();

			IEnumerable<ServiceDescriptor> serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
			Assert.Equal(2, serviceDescriptors.Count());

			ServiceDescriptor serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
		}

		[Fact]
		public void AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>();

			ServiceDescriptor serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			ServiceProvider sp = services.BuildServiceProvider();
			IApiKeyAuthenticationService provider = sp.GetService<IApiKeyAuthenticationService>();

			Assert.NotNull(provider);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
		}


		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInHeaderOrQueryParams_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInHeaderOrQueryParams(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddApiKeyInQueryParams_allows_chaining_default()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams());
		}

		[Fact]
		public void AddApiKeyInQueryParams_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInQueryParams_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(string.Empty));
		}

		[Fact]
		public void AddApiKeyInQueryParams_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInQueryParams_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInQueryParams()
				.AddApiKeyInQueryParams(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}


		[Fact]
		public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>());
		}

		[Fact]
		public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(_ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_scheme()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(string.Empty));
		}

		[Fact]
		public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_scheme_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public void AddApiKeyInQueryParams_TApiKeyProvider_allows_chaining_with_scheme_displayName_and_configureOptions()
		{
			AuthenticationBuilder authenticationBuilder = new ServiceCollection().AddAuthentication();
			Assert.Same(authenticationBuilder, authenticationBuilder.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(string.Empty, string.Empty, _ =>
			{
			}));
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_TApiKeyProvider_allows_multiple_schemes()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";

			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>()
				.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
				{
				});

			ServiceProvider sp = services.BuildServiceProvider();
			IAuthenticationSchemeProvider schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
			AuthenticationScheme defaultScheme = await schemeProvider.GetSchemeAsync(ApiKeyDefaults.AuthenticationScheme);
			AuthenticationScheme scheme = await schemeProvider.GetSchemeAsync(schemeName);

			Assert.NotNull(defaultScheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), defaultScheme.HandlerType.Name);
			Assert.Null(defaultScheme.DisplayName);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, defaultScheme.Name);

			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public void AddApiKeyInQueryParams_TApiKeyProvider_does_not_replace_previously_user_registered_IApiKeyProvider()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddSingleton<IApiKeyAuthenticationService, MockApiKeyProvider2>();
			services.AddAuthentication()
				.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>();

			IEnumerable<ServiceDescriptor> serviceDescriptors = services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService));
			Assert.Equal(2, serviceDescriptors.Count());

			ServiceDescriptor serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			serviceDescriptor = Assert.Single(serviceDescriptors.Where(s => s.ImplementationType == typeof(MockApiKeyProvider2)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyProvider2), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Singleton, serviceDescriptor.Lifetime);
		}

		[Fact]
		public void AddApiKeyInQueryParams_TApiKeyProvider_IApiKeyProvider_is_registered_as_transient()
		{
			ServiceCollection services = new ServiceCollection();
			services.AddAuthentication()
				.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>();

			ServiceDescriptor serviceDescriptor = Assert.Single(services.Where(s => s.ServiceType == typeof(IApiKeyAuthenticationService)));
			Assert.Equal(typeof(IApiKeyAuthenticationService), serviceDescriptor.ServiceType);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), serviceDescriptor.ImplementationType);
			Assert.Equal(ServiceLifetime.Transient, serviceDescriptor.Lifetime);

			ServiceProvider sp = services.BuildServiceProvider();
			IApiKeyAuthenticationService provider = sp.GetService<IApiKeyAuthenticationService>();

			Assert.NotNull(provider);
			Assert.Equal(typeof(MockApiKeyAuthenticationService), provider.GetType());
		}


		[Fact]
		public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_TApiKeyProvider_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams<MockApiKeyAuthenticationService>(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_default()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams());
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_configureOptions()
		{
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams(_ =>
			{
			}));
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_scheme()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams(schemeName), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_scheme_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams(schemeName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.Null(scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}

		[Fact]
		public async Task AddApiKeyInQueryParams_verify_auth_scheme_handler_with_scheme_displayName_and_configureOptions()
		{
			string schemeName = "CustomScheme";
			string displayName = "DisplayName";
			AuthenticationScheme scheme = await this.GetSchemeAsync(a => a.AddApiKeyInQueryParams(schemeName, displayName, _ =>
			{
			}), schemeName);
			Assert.NotNull(scheme);
			Assert.Equal(nameof(ApiKeyInQueryParamsHandler), scheme.HandlerType.Name);
			Assert.NotNull(scheme.DisplayName);
			Assert.Equal(displayName, scheme.DisplayName);
			Assert.Equal(schemeName, scheme.Name);
		}
	}
}
