// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
	using System;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.TestHost;
	using Xunit;

	public class ApiKeyPostConfigureOptionsTests
	{
		private static readonly string KeyName = "X-API-KEY";

		private async Task RunAuthInitAsync(Action<ApiKeyOptions> configureOptions)
		{
			TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServer(configureOptions);
			await server.CreateClient().GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
		}

		private async Task RunAuthInitWithProviderAsync(Action<ApiKeyOptions> configureOptions)
		{
			TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(configureOptions);
			await server.CreateClient().GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
		}

		private async Task RunAuthInitWithServiceFactoryAsync(Action<ApiKeyOptions> configureOptions)
		{
			TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProviderFactory(configureOptions);
			await server.CreateClient().GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_not_set_and_IApiKeyProvider_not_set_but_IApiKeyProviderFactory_registered_no_exception_thrown()
		{
			await this.RunAuthInitWithServiceFactoryAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
				options.KeyName = KeyName;
			});
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_not_set_but_IApiKeyProvider_set_no_exception_thrown()
		{
			await this.RunAuthInitWithProviderAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
				options.KeyName = KeyName;
			});
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_or_IApiKeyProvider_or_IApiKeyProviderFactory_not_set_throws_exception()
		{
			InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => this.RunAuthInitAsync(options =>
				{
					options.SuppressWWWAuthenticateHeader = true;
					options.KeyName = KeyName;
				})
			);

			Assert.Contains($"Either {nameof(ApiKeyOptions.Events.OnValidateKey)} delegate on configure options {nameof(ApiKeyOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IApiKeyAuthenticationService)} or register an implementation of type {nameof(IApiKeyAuthenticationServiceFactory)} in the service collection.", exception.Message);
		}

		[Fact]
		public async Task PostConfigure_Events_OnValidateKey_set_but_IApiKeyProvider_not_set_no_exception_thrown()
		{
			await this.RunAuthInitAsync(options =>
			{
				options.Events.OnValidateKey = _ => Task.CompletedTask;
				options.SuppressWWWAuthenticateHeader = true;
				options.KeyName = KeyName;
			});
		}

		[Fact]
		public async Task PostConfigure_KeyName_not_set_throws_exception()
		{
			InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => this.RunAuthInitWithProviderAsync(options =>
				{
					options.SuppressWWWAuthenticateHeader = true;
				})
			);

			Assert.Contains($"{nameof(ApiKeyOptions.KeyName)} must be set in {nameof(ApiKeyOptions)} when setting up the authentication.", exception.Message);
		}

		[Fact]
		public async Task PostConfigure_KeyName_set_no_exception_thrown()
		{
			await this.RunAuthInitWithProviderAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
				options.KeyName = KeyName;
			});
		}

		[Fact]
		public async Task PostConfigure_no_option_set_throws_exception()
		{
			await Assert.ThrowsAsync<InvalidOperationException>(() => this.RunAuthInitAsync(_ =>
			{
			}));
		}

		[Fact]
		public async Task PostConfigure_Realm_not_set_but_SuppressWWWAuthenticateHeader_set_no_exception_thrown()
		{
			await this.RunAuthInitWithProviderAsync(options =>
			{
				options.SuppressWWWAuthenticateHeader = true;
				options.KeyName = KeyName;
			});
		}

		[Fact]
		public async Task PostConfigure_Realm_or_SuppressWWWAuthenticateHeader_not_set_throws_exception()
		{
			InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => this.RunAuthInitWithProviderAsync(options =>
				{
					options.KeyName = KeyName;
				})
			);

			Assert.Contains($"{nameof(ApiKeyOptions.Realm)} must be set in {nameof(ApiKeyOptions)} when setting up the authentication.", exception.Message);
		}

		[Fact]
		public async Task PostConfigure_Realm_set_but_SuppressWWWAuthenticateHeader_not_set_no_exception_thrown()
		{
			await this.RunAuthInitWithProviderAsync(options =>
			{
				options.Realm = "Test";
				options.KeyName = KeyName;
			});
		}
	}
}
