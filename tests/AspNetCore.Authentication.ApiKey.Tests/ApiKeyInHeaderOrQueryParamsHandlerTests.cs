﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

using AspNetCore.Authentication.ApiKey.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Xunit;

namespace AspNetCore.Authentication.ApiKey.Tests
{
    public class ApiKeyInHeaderOrQueryParamsHandlerTests : IDisposable
    {
		private readonly TestServer _server;
        private readonly HttpClient _client;
        private readonly TestServer _serverWithProvider;
        private readonly HttpClient _clientWithProvider;
		private readonly TestServer _serverWithProviderFactory;
		private readonly HttpClient _clientWithProviderFactory;

        public ApiKeyInHeaderOrQueryParamsHandlerTests()
        {
			_server = TestServerBuilder.BuildInHeaderOrQueryParamsServer();
			_client = _server.CreateClient();

			_serverWithProvider = TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			_clientWithProvider = _serverWithProvider.CreateClient();

			_serverWithProviderFactory = TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProviderFactory();
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
			Assert.Equal(typeof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType);

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
			Assert.Equal(typeof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType);

			var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			var apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.Events?.OnValidateKey);
			Assert.NotNull(apiKeyOptions.ApiKeyProviderType);
			Assert.Equal(typeof(FakeApiKeyAuthenticationService), apiKeyOptions.ApiKeyProviderType);

			var apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(FakeApiKeyAuthenticationService), apiKeyProvider.GetType());
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_Verify_Handler()
		{
			var services = _serverWithProviderFactory.Host.Services;
			var schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			var scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(ApiKeyInHeaderOrQueryParamsHandler), scheme.HandlerType);

			var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
			var apiKeyOptions = apiKeyOptionsSnapshot.Get(scheme.Name);
			Assert.NotNull(apiKeyOptions);
			Assert.Null(apiKeyOptions.Events?.OnValidateKey);
			Assert.Null(apiKeyOptions.ApiKeyProviderType);

			var apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
			Assert.Null(apiKeyProvider);

			var apiKeyProviderFactory = services.GetService<IApiKeyAuthenticationServiceFactory>();
			Assert.NotNull(apiKeyProviderFactory);
			Assert.Equal(typeof(FakeApiKeyAuthenticationServiceFactory), apiKeyProviderFactory.GetType());
		}

		[Fact]
		public async Task Verify_challenge_www_authenticate_header()
		{
			using var response = await _client.GetAsync(TestServerBuilder.BaseUrl);
			Assert.False(response.IsSuccessStatusCode);

			var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{TestServerBuilder.Realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
        public async Task Unauthorized()
        {
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

		[Fact]
		public async Task InHeader_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Add(FakeApiKeys.KeyName, FakeApiKeys.FakeKey);
			using var response = await _client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task InHeader_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Add(FakeApiKeys.KeyName, FakeApiKeys.FakeInvalidKey);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task InAuthorizationHeader_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(FakeApiKeys.KeyName, FakeApiKeys.FakeKey);
			using var response = await _client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task InAuthorizationHeader_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(FakeApiKeys.KeyName, FakeApiKeys.FakeInvalidKey);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task InQueryParams_success()
		{
			var uri = $"{TestServerBuilder.BaseUrl}?{FakeApiKeys.KeyName}={FakeApiKeys.FakeKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task InQueryParams_invalid_key_unauthorized()
		{
			var uri = $"{TestServerBuilder.BaseUrl}?{FakeApiKeys.KeyName}={FakeApiKeys.FakeInvalidKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}



		[Fact]
		public async Task TApiKeyProvider_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InHeader_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Add(FakeApiKeys.KeyName, FakeApiKeys.FakeKey);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InHeader_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Add(FakeApiKeys.KeyName, FakeApiKeys.FakeInvalidKey);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InAuthorizationHeader_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(FakeApiKeys.KeyName, FakeApiKeys.FakeKey);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InAuthorizationHeader_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(FakeApiKeys.KeyName, FakeApiKeys.FakeInvalidKey);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InQueryParams_success()
		{
			var uri = $"{TestServerBuilder.BaseUrl}?{FakeApiKeys.KeyName}={FakeApiKeys.FakeKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_InQueryParams_invalid_key_unauthorized()
		{
			var uri = $"{TestServerBuilder.BaseUrl}?{FakeApiKeys.KeyName}={FakeApiKeys.FakeInvalidKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProvider.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}


		[Fact]
		public async Task TApiKeyProvider_Via_Factory_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InHeader_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Add(FakeApiKeys.KeyName, FakeApiKeys.FakeKey);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InHeader_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Add(FakeApiKeys.KeyName, FakeApiKeys.FakeInvalidKey);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InAuthorizationHeader_success()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(FakeApiKeys.KeyName, FakeApiKeys.FakeKey);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InAuthorizationHeader_invalid_key_unauthorized()
		{
			using var request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(FakeApiKeys.KeyName, FakeApiKeys.FakeInvalidKey);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InQueryParams_success()
		{
			var uri = $"{TestServerBuilder.BaseUrl}?{FakeApiKeys.KeyName}={FakeApiKeys.FakeKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task TApiKeyProvider_Via_Factory_InQueryParams_invalid_key_unauthorized()
		{
			var uri = $"{TestServerBuilder.BaseUrl}?{FakeApiKeys.KeyName}={FakeApiKeys.FakeInvalidKey}";
			using var request = new HttpRequestMessage(HttpMethod.Get, uri);
			using var response = await _clientWithProviderFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}
	}
}
