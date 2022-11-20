// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
	using System;
	using System.Net;
	using System.Net.Http;
	using System.Net.Http.Headers;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.TestHost;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.Options;
	using Xunit;

	public class ApiKeyOptionsTests
	{
		[Fact]
		public void ApiKeyProviderType_default_null()
		{
			ApiKeyOptions options = new ApiKeyOptions();
			Assert.Null(options.ApiKeyProviderType);
		}

		[Fact]
		public void ApiKeyProviderType_verify_not_null()
		{
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			IServiceProvider services = server.Host.Services;

			IOptionsSnapshot<ApiKeyOptions> apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			ApiKeyOptions apiKeyOptions = apiKeyOptionsSnapshot.Get(ApiKeyDefaults.AuthenticationScheme);
			Assert.NotNull(apiKeyOptions);
			Assert.NotNull(apiKeyOptions.ApiKeyProviderType);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyOptions.ApiKeyProviderType);

			IApiKeyAuthenticationService apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyProvider.GetType());
		}

		[Fact]
		public void ApiKeyProviderType_verify_null()
		{
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServer();
			IServiceProvider services = server.Host.Services;

			IOptionsSnapshot<ApiKeyOptions> apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			ApiKeyOptions apiKeyOptions = apiKeyOptionsSnapshot.Get(ApiKeyDefaults.AuthenticationScheme);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.ApiKeyProviderType);

			IApiKeyAuthenticationService apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.Null(apiKeyProvider);
		}

		[Fact]
		public void Events_default_not_null()
		{
			ApiKeyOptions options = new ApiKeyOptions();
			Assert.NotNull(options.Events);
		}

		[Fact]
		public void ForLegacyIgnoreExtraValidatedApiKeyCheck_default_false()
		{
			ApiKeyOptions options = new ApiKeyOptions();
			Assert.False(options.ForLegacyIgnoreExtraValidatedApiKeyCheck);
		}

		[Fact]
		public async Task ForLegacyIgnoreExtraValidatedApiKeyCheck_verify_false()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.ForLegacyIgnoreExtraValidatedApiKeyCheck = false;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck);
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task ForLegacyIgnoreExtraValidatedApiKeyCheck_verify_true()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.ForLegacyIgnoreExtraValidatedApiKeyCheck = true;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck);
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public void ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader_default_false()
		{
			ApiKeyOptions options = new ApiKeyOptions();
			Assert.False(options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader);
		}

		[Fact]
		public async Task ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader_verify_false()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader = false;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

			HttpHeaderValueCollection<AuthenticationHeaderValue> wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			AuthenticationHeaderValue wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.NotEqual(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public async Task ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader_verify_true()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader = true;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

			HttpHeaderValueCollection<AuthenticationHeaderValue> wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			AuthenticationHeaderValue wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.NotEqual(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public void SuppressWWWAuthenticateHeader_default_false()
		{
			ApiKeyOptions options = new ApiKeyOptions();
			Assert.False(options.SuppressWWWAuthenticateHeader);
		}

		[Fact]
		public async Task SuppressWWWAuthenticateHeader_verify_false()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.SuppressWWWAuthenticateHeader = false;
			});

			using HttpClient client = server.CreateClient();
			using HttpResponseMessage response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);

			HttpHeaderValueCollection<AuthenticationHeaderValue> wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			AuthenticationHeaderValue wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public async Task SuppressWWWAuthenticateHeader_verify_true()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.SuppressWWWAuthenticateHeader = true;
			});

			using HttpClient client = server.CreateClient();
			using HttpResponseMessage response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
		}

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

		[Fact]
		public void IgnoreAuthenticationIfAllowAnonymous_default_false()
		{
			ApiKeyOptions options = new ApiKeyOptions();
			Assert.False(options.IgnoreAuthenticationIfAllowAnonymous);
		}

		[Fact]
		public async Task IgnoreAuthenticationIfAllowAnonymous_verify_false()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.IgnoreAuthenticationIfAllowAnonymous = false;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyIgnoreAuthenticationIfAllowAnonymous);

			InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.SendAsync(request));

			Assert.Equal(nameof(ApiKeyOptions.IgnoreAuthenticationIfAllowAnonymous), exception.Message);
		}

		[Fact]
		public async Task IgnoreAuthenticationIfAllowAnonymous_verify_true()
		{
			string realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
			using TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = realm;
				options.IgnoreAuthenticationIfAllowAnonymous = true;
			});

			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyIgnoreAuthenticationIfAllowAnonymous);
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

#endif
	}
}
