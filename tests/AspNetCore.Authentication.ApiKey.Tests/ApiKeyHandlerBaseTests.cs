// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.Extensions.DependencyInjection;
    using Xunit;

    public class ApiKeyHandlerBaseTests 
    {
		private const string HeaderFromEventsKey = nameof(HeaderFromEventsKey);
		private const string HeaderFromEventsValue = nameof(HeaderFromEventsValue);

		#region HandleForbidden

		[Fact]
		public async Task HandleForbidden()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ForbiddenUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
			Assert.False(response.Headers.Contains(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleForbidden_using_OnHandleForbidden()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnHandleForbidden = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ForbiddenUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		#endregion // HandleForbidden

		#region HandleChallenge

		[Fact]
		public async Task HandleChallange()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallange_using_OnHandleChallenge()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleChallange_using_SuppressWWWAuthenticateHeader()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.SuppressWWWAuthenticateHeader = true;
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallange_using_OnHandleChallenge_and_SuppressWWWAuthenticateHeader()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.SuppressWWWAuthenticateHeader = true;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		#endregion // HandleChallenge

		#region HandleAuthenticate

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

		[Fact]
		public async Task HandleAuthenticate_IgnoreAuthenticationIfAllowAnonymous()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			using var client = server.CreateClient();
			using var response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.AnonymousUrl);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.False(principal.Identity.IsAuthenticated);
		}

#endif

		[Fact]
		public async Task HandleAuthenticate_ParseApiKey_empty()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, string.Empty);
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateKey_result_not_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnValidateKey = context =>
				{
					context.ValidationSucceeded();

					Assert.NotNull(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.DoesNotContain(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeRoleClaim), principal.Claims);		// provider not called
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateKey_result_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnValidateKey = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);
			var principal = await DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeRoleClaim), principal.Claims);		// coming from provider, so provider called
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateKey_result_null_without_provider_and_OnAuthenticationFailed_throws()
		{
			var expectedExceptionMessage = $"Either {nameof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyEvents.OnValidateKey)} delegate on configure options {nameof(ApiKeyOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IApiKeyAuthenticationService)} or register an implementation of type {nameof(IApiKeyAuthenticationServiceFactory)} in the service collection.";

			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServer(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnValidateKey = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};

				options.Events.OnAuthenticationFailed = context =>
				{
					Assert.NotNull(context.Exception);
					Assert.IsType<InvalidOperationException>(context.Exception);
					Assert.Equal(expectedExceptionMessage, context.Exception.Message);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);

			var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
			{
				using var response = await client.SendAsync(request);

				Assert.False(response.IsSuccessStatusCode);
				Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			});

			Assert.Equal(expectedExceptionMessage, exception.Message);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateKey_result_null_without_provider_and_OnAuthenticationFailed_does_not_throw()
		{
			var expectedExceptionMessage = $"Either {nameof(MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyEvents.OnValidateKey)} delegate on configure options {nameof(ApiKeyOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IApiKeyAuthenticationService)} or register an implementation of type {nameof(IApiKeyAuthenticationServiceFactory)} in the service collection.";

			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServer(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnValidateKey = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};

				options.Events.OnAuthenticationFailed = context =>
				{
					Assert.Null(context.Result);
					Assert.NotNull(context.Exception);
					Assert.IsType<InvalidOperationException>(context.Exception);
					Assert.Equal(expectedExceptionMessage, context.Exception.Message);

					context.NoResult();

					Assert.NotNull(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_ForLegacyIgnoreExtraValidatedApiKeyCheck()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider();
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck);
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_and_principal_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.RejectPrincipal();
					
					Assert.Null(context.Result);
					Assert.Null(context.Principal);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_not_null()
		{
			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.Fail("test");

					Assert.NotNull(context.Result);
					Assert.NotNull(context.Principal);

					return Task.CompletedTask;
				};
			});
			using var client = server.CreateClient();
			using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using var response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

        #endregion // HandleAuthenticate

        #region Multi-Scheme

        [Fact]
        public async Task MultiScheme()
        {
            var keyName1 = "Key1";
            var keyName2 = "Key2";
            var keyName3 = "Key3";
            var keyName4 = "Key4";
            var claimProvider1 = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto { Type = "Provider", Value = "1" };
            var claimProvider2 = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto { Type = "Provider", Value = "2" };
            var claimRole = new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeRoleClaim);
			var schemes = new List<string> { "InHeader", "InHeaderWithProvider", "InAuthorizationHeader", "InQueryParams" };

			using var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildTestServer(services =>
            {
                services.AddAuthentication("InHeader")
                    .AddApiKeyInHeader("InHeader", options =>
                    {
                        options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
                        options.KeyName = keyName1;
                        options.Events.OnValidateKey = context =>
                        {
                            context.Response.Headers.Add("X-Custom", "InHeader Scheme");
                            context.ValidationSucceeded();
                            return Task.CompletedTask;
                        };
                    })
                    .AddApiKeyInHeader<FakeApiKeyAuthenticationServiceLocal1>("InHeaderWithProvider", options =>
                    {
                        options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
                        options.KeyName = keyName2;
                    })
                    .AddApiKeyInAuthorizationHeader<FakeApiKeyAuthenticationServiceLocal2>("InAuthorizationHeader", options =>
                    {
                        options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
                        options.KeyName = keyName3;
                    })
                    .AddApiKeyInQueryParams<MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeyAuthenticationService>("InQueryParams", options =>
                    {
                        options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
                        options.KeyName = keyName4;
                    });

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
				services.Configure<AuthorizationOptions>(options => options.FallbackPolicy = new AuthorizationPolicyBuilder(schemes.ToArray()).RequireAuthenticatedUser().Build());
#endif
			});

            using var client = server.CreateClient();

            using var request1 = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[0]);
            request1.Headers.Add(keyName1, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
            using var response1 = await client.SendAsync(request1);
            Assert.True(response1.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response1.StatusCode);
            var response1Principal = await DeserializeClaimsPrincipalAsync(response1);
            Assert.Contains(response1.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "InHeader Scheme"));
            Assert.DoesNotContain(response1Principal.Claims, c => c.Type == claimProvider1.Type && c.Value == claimProvider1.Value);
            Assert.DoesNotContain(response1Principal.Claims, c => c.Type == claimProvider2.Type && c.Value == claimProvider2.Value);
            Assert.DoesNotContain(response1Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);


            using var request2 = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[1]);
            request2.Headers.Add(keyName2, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
            using var response2 = await client.SendAsync(request2);
            Assert.True(response2.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
            var response2Principal = await DeserializeClaimsPrincipalAsync(response2);
            Assert.DoesNotContain(response2.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "InHeader Scheme"));
            Assert.Contains(response2Principal.Claims, c => c.Type == claimProvider1.Type && c.Value == claimProvider1.Value);
            Assert.DoesNotContain(response2Principal.Claims, c => c.Type == claimProvider2.Type && c.Value == claimProvider2.Value);
            Assert.DoesNotContain(response2Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);


            using var request3 = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[2]);
            request3.Headers.Authorization = new AuthenticationHeaderValue(keyName3, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
            using var response3 = await client.SendAsync(request3);
            Assert.True(response3.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response3.StatusCode);
            var response3Principal = await DeserializeClaimsPrincipalAsync(response3);
            Assert.DoesNotContain(response3.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "InHeader Scheme"));
            Assert.DoesNotContain(response3Principal.Claims, c => c.Type == claimProvider1.Type && c.Value == claimProvider1.Value);
            Assert.Contains(response3Principal.Claims, c => c.Type == claimProvider2.Type && c.Value == claimProvider2.Value);
            Assert.DoesNotContain(response3Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);


            using var request4 = new HttpRequestMessage(HttpMethod.Get, $"{MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl}?scheme={schemes[3]}&{keyName4}={MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey}");
            using var response4 = await client.SendAsync(request4);
            Assert.True(response4.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response3.StatusCode);
            var response4Principal = await DeserializeClaimsPrincipalAsync(response4);
            Assert.DoesNotContain(response4.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "InHeader Scheme"));
            Assert.DoesNotContain(response4Principal.Claims, c => c.Type == claimProvider1.Type && c.Value == claimProvider1.Value);
            Assert.DoesNotContain(response4Principal.Claims, c => c.Type == claimProvider2.Type && c.Value == claimProvider2.Value);
            Assert.Contains(response4Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);
        }

        #endregion // Multi-Scheme

        private async Task<MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimsPrincipalDto> DeserializeClaimsPrincipalAsync(HttpResponseMessage response)
        {
			return JsonSerializer.Deserialize<MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimsPrincipalDto>(await response.Content.ReadAsStringAsync());
		}

        private class FakeApiKeyAuthenticationServiceLocal1 : IApiKeyAuthenticationService
        {
            public Task<IApiKey> AuthenticateAsync(string key)
            {
				return Task.FromResult((IApiKey)new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKey(key, "Test", new List<Claim> { new Claim("Provider", "1") }));
            }
        }

		private class FakeApiKeyAuthenticationServiceLocal2 : IApiKeyAuthenticationService
		{
			public Task<IApiKey> AuthenticateAsync(string key)
			{
				return Task.FromResult((IApiKey)new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKey(key, "Test", new List<Claim> { new Claim("Provider", "2") }));
			}
		}
	}
}
