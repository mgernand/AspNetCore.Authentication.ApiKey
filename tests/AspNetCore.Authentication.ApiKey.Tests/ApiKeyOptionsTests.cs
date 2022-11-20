// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
    using System;
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Options;
    using Xunit;

    public class ApiKeyOptionsTests
    {
        [Fact]
        public void Events_default_not_null()
        {
            var options = new ApiKeyOptions();
            Assert.NotNull(options.Events);
        }

        [Fact]
        public void SuppressWWWAuthenticateHeader_default_false()
        {
            var options = new ApiKeyOptions();
            Assert.False(options.SuppressWWWAuthenticateHeader);
        }

        [Fact]
        public async Task SuppressWWWAuthenticateHeader_verify_false()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.SuppressWWWAuthenticateHeader = false;
            });

            using var client = server.CreateClient();
            using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
            
            Assert.False(response.IsSuccessStatusCode);

            var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
            Assert.NotEmpty(wwwAuthenticateHeader);

            var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
            Assert.NotNull(wwwAuthenticateHeaderToMatch);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
            Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
        }

        [Fact]
        public async Task SuppressWWWAuthenticateHeader_verify_true()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.SuppressWWWAuthenticateHeader = true;
            });

            using var client = server.CreateClient();
            using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

            Assert.False(response.IsSuccessStatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
        }

        [Fact]
        public void ForLegacyIgnoreExtraValidatedApiKeyCheck_default_false()
        {
            var options = new ApiKeyOptions();
            Assert.False(options.ForLegacyIgnoreExtraValidatedApiKeyCheck);
        }

        [Fact]
        public async Task ForLegacyIgnoreExtraValidatedApiKeyCheck_verify_false()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.ForLegacyIgnoreExtraValidatedApiKeyCheck = false;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
            request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck);
            using var response = await client.SendAsync(request);

            Assert.False(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ForLegacyIgnoreExtraValidatedApiKeyCheck_verify_true()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.ForLegacyIgnoreExtraValidatedApiKeyCheck = true;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
            request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck);
            using var response = await client.SendAsync(request);

            Assert.True(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public void ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader_default_false()
        {
            var options = new ApiKeyOptions();
            Assert.False(options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader);
        }

        [Fact]
        public async Task ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader_verify_false()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader = false;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
            using var response = await client.SendAsync(request);

            Assert.False(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
            Assert.NotEmpty(wwwAuthenticateHeader);

            var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
            Assert.NotNull(wwwAuthenticateHeaderToMatch);
            Assert.Equal(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
            Assert.NotEqual(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, wwwAuthenticateHeaderToMatch.Scheme);
            Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
        }

        [Fact]
        public async Task ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader_verify_true()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.ForLegacyUseKeyNameAsSchemeNameOnWWWAuthenticateHeader = true;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
            using var response = await client.SendAsync(request);

            Assert.False(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

            var wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
            Assert.NotEmpty(wwwAuthenticateHeader);

            var wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
            Assert.NotNull(wwwAuthenticateHeaderToMatch);
            Assert.NotEqual(ApiKeyDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
            Assert.Equal(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, wwwAuthenticateHeaderToMatch.Scheme);
            Assert.Equal($"realm=\"{realm}\", charset=\"UTF-8\", in=\"header_or_query_params\", key_name=\"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName}\"", wwwAuthenticateHeaderToMatch.Parameter);
        }

        [Fact]
        public void ApiKeyProviderType_default_null()
        {
            var options = new ApiKeyOptions();
            Assert.Null(options.ApiKeyProviderType);
        }

        [Fact]
        public void ApiKeyProviderType_verify_null()
        {
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServer();
            var services = server.Host.Services;
            
            var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
            var apiKeyOptions = apiKeyOptionsSnapshot.Get(ApiKeyDefaults.AuthenticationScheme);
            Assert.NotNull(apiKeyOptions);
            Assert.Null(apiKeyOptions.ApiKeyProviderType);

            var apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
            Assert.Null(apiKeyProvider);
        }

        [Fact]
        public void ApiKeyProviderType_verify_not_null()
        {
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
            var services = server.Host.Services;

            var apiKeyOptionsSnapshot = services.GetService<IOptionsSnapshot<ApiKeyOptions>>();
            var apiKeyOptions = apiKeyOptionsSnapshot.Get(ApiKeyDefaults.AuthenticationScheme);
            Assert.NotNull(apiKeyOptions);
            Assert.NotNull(apiKeyOptions.ApiKeyProviderType);
            Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyOptions.ApiKeyProviderType);

            var apiKeyProvider = services.GetService<IApiKeyAuthenticationService>();
            Assert.NotNull(apiKeyProvider);
            Assert.Equal(typeof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService), apiKeyProvider.GetType());
        }

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

        [Fact]
        public void IgnoreAuthenticationIfAllowAnonymous_default_false()
        {
            var options = new ApiKeyOptions();
            Assert.False(options.IgnoreAuthenticationIfAllowAnonymous);
        }

        [Fact]
        public async Task IgnoreAuthenticationIfAllowAnonymous_verify_false()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.IgnoreAuthenticationIfAllowAnonymous = false;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
            request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyIgnoreAuthenticationIfAllowAnonymous);

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client.SendAsync(request));

            Assert.Equal(nameof(ApiKeyOptions.IgnoreAuthenticationIfAllowAnonymous), exception.Message);
        }

        [Fact]
        public async Task IgnoreAuthenticationIfAllowAnonymous_verify_true()
        {
            var realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
            using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = realm;
                options.IgnoreAuthenticationIfAllowAnonymous = true;
            });

            using var client = server.CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
            request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyIgnoreAuthenticationIfAllowAnonymous);
            using var response = await client.SendAsync(request);

            Assert.True(response.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

#endif

    }
}
