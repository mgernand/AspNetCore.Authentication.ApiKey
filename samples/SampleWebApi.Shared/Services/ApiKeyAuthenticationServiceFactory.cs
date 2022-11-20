using Microsoft.Extensions.Logging;
using SampleWebApi.Repositories;
using System.Diagnostics;

namespace SampleWebApi.Services
{
	internal class ApiKeyAuthenticationServiceFactory : MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKeyAuthenticationServiceFactory
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly IApiKeyRepository apiKeyRepository;

		public ApiKeyAuthenticationServiceFactory(ILoggerFactory loggerFactory, IApiKeyRepository apiKeyRepository)
		{
			this.loggerFactory = loggerFactory;
			this.apiKeyRepository = apiKeyRepository;
		}

		/// <inheritdoc />
		public MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKeyAuthenticationService CreateApiKeyAuthenticationService(string authenticationSchemaName)
		{
			Debug.WriteLine(authenticationSchemaName);
			return new ApiKeyAuthenticationService(loggerFactory.CreateLogger<ApiKeyAuthenticationService>(), this.apiKeyRepository);
		}
	}
}
