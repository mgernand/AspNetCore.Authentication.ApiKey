// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Events
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Net;
	using System.Net.Http;
	using System.Security.Claims;
	using System.Text.Json;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure;
	using Microsoft.AspNetCore.TestHost;
	using Xunit;

	public class ApiKeyValidateKeyContextTests : IDisposable
	{
		public void Dispose()
		{
			this._serversToDispose.ForEach(s => s.Dispose());
		}

		private readonly List<TestServer> _serversToDispose = new List<TestServer>();


		private HttpClient BuildClient(Func<MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyValidateKeyContext, Task> onValidateKey)
		{
			TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServer(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnValidateKey = onValidateKey;
			});

			this._serversToDispose.Add(server);
			return server.CreateClient();
		}

		private async Task RunUnauthorizedTests(HttpClient client)
		{
			using HttpResponseMessage response_unauthorized = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			Assert.False(response_unauthorized.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response_unauthorized.StatusCode);
		}

		private async Task<MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimsPrincipalDto> RunSuccessTests(HttpClient client)
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Add(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName, MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeKey);
			using HttpResponseMessage response_ok = await client.SendAsync(request);
			Assert.True(response_ok.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response_ok.StatusCode);

			string content = await response_ok.Content.ReadAsStringAsync();
			Assert.False(string.IsNullOrWhiteSpace(content));
			return JsonSerializer.Deserialize<MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimsPrincipalDto>(content);
		}

		[Fact]
		public async Task Success_and_NoResult()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Assert.Null(context.Principal);
					Assert.Null(context.Result);
					Assert.False(string.IsNullOrWhiteSpace(context.ApiKey));

					IApiKey apiKey = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.Keys.FirstOrDefault(k => k.Key.Equals(context.ApiKey, StringComparison.OrdinalIgnoreCase));
					if(apiKey != null)
					{
						context.Principal = new ClaimsPrincipal(new ClaimsIdentity(context.Scheme.Name));
						context.Success();

						Assert.NotNull(context.Principal);
						Assert.NotNull(context.Result);
						Assert.NotNull(context.Result.Principal);
						Assert.True(context.Result.Succeeded);
					}
					else
					{
						context.NoResult();

						Assert.Null(context.Principal);
						Assert.NotNull(context.Result);
						Assert.Null(context.Result.Principal);
						Assert.False(context.Result.Succeeded);
						Assert.True(context.Result.None);
					}

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.Empty(principal.Claims);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationFailed_with_failureException()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Exception failureException = new Exception();
					context.ValidationFailed(failureException);

					Assert.Null(context.Principal);
					Assert.NotNull(context.Result);
					Assert.Null(context.Result.Principal);
					Assert.False(context.Result.Succeeded);
					Assert.NotNull(context.Result.Failure);
					Assert.Equal(failureException, context.Result.Failure);

					return Task.CompletedTask;
				}
			);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationFailed_with_failureMessage()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					string failureMessage = "failure message";
					context.ValidationFailed(failureMessage);

					Assert.Null(context.Principal);
					Assert.NotNull(context.Result);
					Assert.Null(context.Result.Principal);
					Assert.False(context.Result.Succeeded);
					Assert.NotNull(context.Result.Failure);
					Assert.Equal(failureMessage, context.Result.Failure.Message);

					return Task.CompletedTask;
				}
			);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationSucceeded_and_ValidationFailed()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					IApiKey apiKey = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.Keys.FirstOrDefault(k => k.Key.Equals(context.ApiKey, StringComparison.OrdinalIgnoreCase));
					if(apiKey != null)
					{
						context.ValidationSucceeded();

						Assert.NotNull(context.Principal);
						Assert.NotNull(context.Result);
						Assert.NotNull(context.Result.Principal);
						Assert.True(context.Result.Succeeded);
					}
					else
					{
						context.ValidationFailed();

						Assert.Null(context.Principal);
						Assert.NotNull(context.Result);
						Assert.Null(context.Result.Principal);
						Assert.False(context.Result.Succeeded);
						Assert.True(context.Result.None);
					}

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.Empty(principal.Claims);

			await this.RunUnauthorizedTests(client);
		}

		[Fact]
		public async Task ValidationSucceeded_with_claims()
		{
			List<Claim> claimsSource = new List<Claim>
			{
				MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeNameClaim,
				MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeRoleClaim
			};

			using HttpClient client = this.BuildClient(
				context =>
				{
					context.ValidationSucceeded(claimsSource);

					Assert.NotNull(context.Principal);
					Assert.NotNull(context.Result);
					Assert.NotNull(context.Result.Principal);
					Assert.True(context.Result.Succeeded);

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.NotEmpty(principal.Claims);

			Assert.Equal(claimsSource.Count, principal.Claims.Count());
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeNameClaim), principal.Claims);
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeRoleClaim), principal.Claims);
		}

		[Fact]
		public async Task ValidationSucceeded_with_ownerName()
		{
			string ownerName = "Owner";

			using HttpClient client = this.BuildClient(
				context =>
				{
					context.ValidationSucceeded(ownerName);

					Assert.NotNull(context.Principal);
					Assert.NotNull(context.Result);
					Assert.NotNull(context.Result.Principal);
					Assert.True(context.Result.Succeeded);

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.NotEmpty(principal.Claims);

			Assert.Equal(2, principal.Claims.Count());
			Assert.Contains(principal.Claims, c => c.Type == ClaimTypes.Name && c.Value == ownerName);
			Assert.Contains(principal.Claims, c => c.Type == ClaimTypes.NameIdentifier && c.Value == ownerName);
		}

		[Fact]
		public async Task ValidationSucceeded_with_ownerName_and_claims()
		{
			string ownerName = "Owner";
			List<Claim> claimsSource = new List<Claim>
			{
				MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeNameClaim,
				MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeRoleClaim
			};

			using HttpClient client = this.BuildClient(
				context =>
				{
					context.ValidationSucceeded(ownerName, claimsSource);

					Assert.NotNull(context.Principal);
					Assert.NotNull(context.Result);
					Assert.NotNull(context.Result.Principal);
					Assert.True(context.Result.Succeeded);

					return Task.CompletedTask;
				}
			);

			ClaimsPrincipalDto principal = await this.RunSuccessTests(client);
			Assert.NotEmpty(principal.Claims);

			Assert.Equal(claimsSource.Count + 1, principal.Claims.Count());
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeNameClaim), principal.Claims);
			Assert.Contains(new MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.ClaimDto(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.FakeRoleClaim), principal.Claims);
			Assert.Contains(principal.Claims, c => c.Type == ClaimTypes.NameIdentifier && c.Value == ownerName);
		}
	}
}
