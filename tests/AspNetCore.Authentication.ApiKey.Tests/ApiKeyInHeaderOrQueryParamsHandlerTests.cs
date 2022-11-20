// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
	using System;
	using System.Net;
	using System.Net.Http;
	using System.Net.Http.Headers;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.TestHost;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.Options;
	using Xunit;

	public class ApiKeyInHeaderOrQueryParamsHandlerTests : IDisposable
	{
		public ApiKeyInHeaderOrQueryParamsHandlerTests()
		{
			this._server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServer();
			this._client = this._server.CreateClient();

			this._serverWithProvider = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			this._clientWithProvider = this._serverWithProvider.CreateClient();

			this._serverWithProviderFactory = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProviderFactory();
			this._clientWithProviderFactory = this._serverWithProvider.CreateClient();
		}

		public void Dispose()
		{
			this._client?.Dispose();
			this._server?.Dispose();

			this._clientWithProvider?.Dispose();
			this._serverWithProvider?.Dispose();

			this._serverWithProviderFactory?.Dispose();
			this._clientWithProviderFactory?.Dispose();
		}

		private readonly TestServer _server;
		private readonly HttpClient _client;
		private readonly TestServer _serverWithProvider;
		private readonly HttpClient _clientWithProvider;
		private readonly TestServer _serverWithProviderFactory;
		private readonly HttpClient _clientWithProviderFactory;

		[Fact]
		public async Task InAuthorizationHeader_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task InAuthorizationHeader_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task InHeader_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task InHeader_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task InQueryParams_invalid_key_unauthorized()
		{
			string uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey}";
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task InQueryParams_success()
		{
			string uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey}";
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InAuthorizationHeader_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey);
			using HttpResponseMessage response = await this._clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InAuthorizationHeader_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using HttpResponseMessage response = await this._clientWithProvider.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InHeader_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey);
			using HttpResponseMessage response = await this._clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InHeader_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using HttpResponseMessage response = await this._clientWithProvider.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InQueryParams_invalid_key_unauthorized()
		{
			string uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey}";
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri);
			using HttpResponseMessage response = await this._clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InQueryParams_success()
		{
			string uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey}";
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri);
			using HttpResponseMessage response = await this._clientWithProvider.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}


		[Fact]
		public async Task TApiKeyProvider_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await this._clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Verify_Handler()
		{
			IServiceProvider services = this._serverWithProvider.Host.Services;
			IAuthenticationSchemeProvider schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			AuthenticationScheme scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType);

			IOptionsSnapshot<ApiKeyOptions> apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			ApiKeyOptions apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.Events?.OnValidateKey);
			Assert.NotNull(apiKeyOptions.ApiKeyProviderType);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyOptions.ApiKeyProviderType);

			IApiKeyAuthenticationService apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyProvider.GetType());
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InAuthorizationHeader_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey);
			using HttpResponseMessage response = await this._clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InAuthorizationHeader_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using HttpResponseMessage response = await this._clientWithProviderFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InHeader_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey);
			using HttpResponseMessage response = await this._clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InHeader_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using HttpResponseMessage response = await this._clientWithProviderFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InQueryParams_invalid_key_unauthorized()
		{
			string uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey}";
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri);
			using HttpResponseMessage response = await this._clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InQueryParams_success()
		{
			string uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey}";
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri);
			using HttpResponseMessage response = await this._clientWithProviderFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}


		[Fact]
		public async Task TApiKeyProvider_Via_Factory_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await this._clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_Verify_Handler()
		{
			IServiceProvider services = this._serverWithProviderFactory.Host.Services;
			IAuthenticationSchemeProvider schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			AuthenticationScheme scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType);

			IOptionsSnapshot<ApiKeyOptions> apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			ApiKeyOptions apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.Events?.OnValidateKey);
			Assert.Null(apiKeyOptions.ApiKeyProviderType);

			IApiKeyAuthenticationService apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.Null(apiKeyProvider);

			IApiKeyAuthenticationServiceFactory apiKeyProviderFactory = services.GetService<IApiKeyAuthenticationServiceFactory>();
			Assert.NotNull(apiKeyProviderFactory);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationServiceFactory), apiKeyProviderFactory.GetType());
		}

		[Fact]
		public async Task Unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task Verify_challenge_www_authenticate_header()
		{
			using HttpResponseMessage response = await this._client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			Assert.False(response.IsSuccessStatusCode);

			HttpHeaderValueCollection<AuthenticationHeaderValue> wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			AuthenticationHeaderValue wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public async Task Verify_Handler()
		{
			IServiceProvider services = this._server.Host.Services;
			IAuthenticationSchemeProvider schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			AuthenticationScheme scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType);

			IOptionsSnapshot<ApiKeyOptions> apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			ApiKeyOptions apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.NotNull(apiKeyOptions.Events?.OnValidateKey);
			Assert.Null(apiKeyOptions.ApiKeyProviderType);

			IApiKeyAuthenticationService apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.Null(apiKeyProvider);
		}
	}
}
