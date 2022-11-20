// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
    using System;
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.TestHost;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Options;
    using Xunit;

    public class ApiKeyInQueryParamsHandlerTests : IDisposable
    {
		private readonly TestServer _server;
        private readonly HttpClient _client;
        private readonly TestServer _serverWithProvider;
        private readonly HttpClient _clientWithProvider;
		private readonly TestServer _serverWithProviderFactory;
		private readonly HttpClient _clientWithProviderFactory;

        public ApiKeyInQueryParamsHandlerTests()
        {
			_server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInQueryParamsServer();
			_client = _server.CreateClient();

			_serverWithProvider = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInQueryParamsServerWithProvider();
			_clientWithProvider = _serverWithProvider.CreateClient();

			_serverWithProviderFactory = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInQueryParamsServerWithProviderFactory();
			_clientWithProviderFactory = _serverWithProvider.CreateClient();
		}

		public void Dispose()
		{
			_client?.Dispose();
			_server?.Dispose();

			_clientWithProvider?.Dispose();
			_serverWithProvider?.Dispose();

			_serverWithProviderFactory?.Dispose();
			_clientWithProviderFactory?.Dispose();
		}

		[Fact]
		public async Task Verify_Handler()
		{
			var services = _server.Host.Services;
			var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);
			
			var scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(ApiKeyInQueryParamsHandler), scheme.HandlerType);

			var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			var apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.NotNull(apiKeyOptions.Events?.OnValidateKey);
			Assert.Null(apiKeyOptions.ApiKeyProviderType);

			var apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.Null(apiKeyProvider);
		}

		[Fact]
		public async Task TApiKeyProvider_Verify_Handler()
		{
			var services = _serverWithProvider.Host.Services;
			var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			var scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(ApiKeyInQueryParamsHandler), scheme.HandlerType);

			var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			var apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.Events?.OnValidateKey);
			Assert.NotNull(apiKeyOptions.ApiKeyProviderType);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyOptions.ApiKeyProviderType);

			var apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyProvider.GetType());
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_Verify_Handler()
		{
			var services = _serverWithProviderFactory.Host.Services;
			var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			var scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(ApiKeyInQueryParamsHandler), scheme.HandlerType);

			var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			var apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.Events?.OnValidateKey);
			Assert.Null(apiKeyOptions.ApiKeyProviderType);

			var apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.Null(apiKeyProvider);

			var apiKeyProviderFactory = services.GetService<IApiKeyAuthenticationServiceFactory>();
			Assert.NotNull(apiKeyProviderFactory);
			Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationServiceFactory), apiKeyProviderFactory.GetType());
		}

		[Fact]
		public async Task Verify_challenge_www_authenticate_header()
		{
			using var response = await _client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			Assert.False(response.IsSuccessStatusCode);

			var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm}\", charset=\"UTF-8\", in=\"query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
        public async Task Unauthorized()
        {
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

		[Fact]
		public async Task Success()
		{
			var uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task Invalid_key_unauthorized()
		{
			var uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}



		[Fact]
		public async Task TApiKeyProvider_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_success()
		{
			var uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_invalid_key_unauthorized()
		{
			var uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}



		[Fact]
		public async Task TApiKeyProvider_Via_Factory_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_success()
		{
			var uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_invalid_key_unauthorized()
		{
			var uri = $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl}?{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeInvalidKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}
	}
}
