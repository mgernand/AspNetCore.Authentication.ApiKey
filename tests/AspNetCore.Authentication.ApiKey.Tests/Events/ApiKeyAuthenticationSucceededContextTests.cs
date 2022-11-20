// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Events
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.TestHost;
    using Xunit;

    public class ApiKeyAuthenticationSucceededContextTests : IDisposable
    {
        private readonly List<TestServer> _serversToDispose = new List<TestServer>();

        public void Dispose()
        {
            _serversToDispose.ForEach(s => s.Dispose());
        }

        [Fact]
        public async Task Principal_not_null()
        {
            using var client = BuildClient(
                context =>
                {
                    Assert.NotNull(context.Principal);
                    Assert.Null(context.Result);
                    return Task.CompletedTask;
                }
            );

            var principal = await RunSuccessTests(client);
            Assert.True(principal.Identity.IsAuthenticated);
        }

        [Fact]
        public async Task ReplacePrincipal_null_throws_argument_null_exception()
        {
            using var client = BuildClient(
                context =>
                {
                    Assert.Throws<ArgumentNullException>(() => context.ReplacePrincipal(null));
                    return Task.CompletedTask;
                }
            );

            await RunSuccessTests(client);
        }

        [Fact]
        public async Task ReplacePrincipal()
        {
            using var client = BuildClient(
                context =>
                {
                    var newPrincipal = new ClaimsPrincipal();
                    context.ReplacePrincipal(newPrincipal);

                    Assert.NotNull(context.Principal);
                    Assert.Equal(newPrincipal, context.Principal);

                    return Task.CompletedTask;
                }
            );

            await RunUnauthorizedTests(client);
        }

        [Fact]
        public async Task RejectPrincipal()
        {
            using var client = BuildClient(
                context =>
                {
                    context.RejectPrincipal();

                    Assert.Null(context.Principal);

                    return Task.CompletedTask;
                }
            );

            await RunUnauthorizedTests(client);
        }

        [Fact]
        public async Task AddClaim()
        {
            var claim = new Claim(ClaimTypes.Actor, "Actor");

            using var client = BuildClient(
                context =>
                {
                    context.AddClaim(claim);

                    Assert.Contains(context.Principal.Claims, c => c.Type == claim.Type && c.Value == claim.Value);

                    return Task.CompletedTask;
                }
            );

            var principal = await RunSuccessTests(client);
            Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(claim), principal.Claims);
        }

        [Fact]
        public async Task AddClaims()
        {
            var claims = new List<Claim>{
                new Claim(ClaimTypes.Actor, "Actor"),
                new Claim(ClaimTypes.Country, "Country")
            };

            using var client = BuildClient(
                context =>
                {
                    context.AddClaims(claims);

                    Assert.Contains(context.Principal.Claims, c => c.Type == claims[0].Type && c.Value == claims[0].Value);
                    Assert.Contains(context.Principal.Claims, c => c.Type == claims[1].Type && c.Value == claims[1].Value);

                    return Task.CompletedTask;
                }
            );

            var principal = await RunSuccessTests(client);
            Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(claims[0]), principal.Claims);
            Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(claims[1]), principal.Claims);
        }



        private HttpClient BuildClient(Func<MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyAuthenticationSucceededContext, Task> onAuthenticationSucceeded)
        {
            var server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
            {
                options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
                options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
                options.Events.OnAuthenticationSucceeded = onAuthenticationSucceeded;
            });

            _serversToDispose.Add(server);
            return server.CreateClient();
        }

        private async Task RunUnauthorizedTests(HttpClient client)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
            request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
            using var response_unauthorized = await client.SendAsync(request);
            Assert.False(response_unauthorized.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, response_unauthorized.StatusCode);
        }

        private async Task<MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimsPrincipalDto> RunSuccessTests(HttpClient client)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
            request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
            using var response_ok = await client.SendAsync(request);
            Assert.True(response_ok.IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, response_ok.StatusCode);

            var content = await response_ok.Content.ReadAsStringAsync();
            Assert.False(string.IsNullOrWhiteSpace(content));
            return JsonSerializer.Deserialize<MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimsPrincipalDto>(content);
        }
    }
}
