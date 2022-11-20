// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Events
{
	using System;
	using System.Collections.Generic;
	using System.Net;
	using System.Net.Http;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.Http;
	using Microsoft.AspNetCore.TestHost;
	using Xunit;

	public class ApiKeyHandleChallengeContextTests : IDisposable
	{
		public void Dispose()
		{
			this._serversToDispose.ForEach(s => s.Dispose());
		}

		private readonly List<TestServer> _serversToDispose = new List<TestServer>();


		private HttpClient BuildClient(Func<MadEyeMatt.AspNetCore.Authentication.ApiKey.Events.ApiKeyHandleChallengeContext, Task> onHandleChallenge)
		{
			TestServer server = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BuildInHeaderOrQueryParamsServerWithProvider(options =>
			{
				options.KeyName = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.FakeApiKeys.KeyName;
				options.Realm = MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.Realm;
				options.Events.OnHandleChallenge = onHandleChallenge;
			});

			this._serversToDispose.Add(server);
			return server.CreateClient();
		}

		[Fact]
		public async Task Handled()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Assert.False(context.IsHandled);

					context.Response.StatusCode = StatusCodes.Status400BadRequest;
					context.Handled();

					Assert.True(context.IsHandled);

					return Task.CompletedTask;
				}
			);

			using HttpResponseMessage response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
		}

		[Fact]
		public async Task Handled_not_called()
		{
			using HttpClient client = this.BuildClient(
				context =>
				{
					Assert.False(context.IsHandled);

					context.Response.StatusCode = StatusCodes.Status400BadRequest;

					return Task.CompletedTask;
				}
			);

			using HttpResponseMessage response = await client.GetAsync(MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure.TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}
	}
}
