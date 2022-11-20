namespace SampleWebApi.Services
{
	using System.Diagnostics;
	using MadEyeMatt.AspNetCore.Authentication.ApiKey;
	using Microsoft.Extensions.Logging;
	using SampleWebApi.Repositories;

	internal class ApiKeyAuthenticationServiceFactory : IApiKeyAuthenticationServiceFactory
	{
		private readonly ILoggerFactory loggerFactory;
		private readonly IApiKeyRepository apiKeyRepository;

		public ApiKeyAuthenticationServiceFactory(ILoggerFactory loggerFactory, IApiKeyRepository apiKeyRepository)
		{
			this.loggerFactory = loggerFactory;
			this.apiKeyRepository = apiKeyRepository;
		}

		/// <inheritdoc />
		public IApiKeyAuthenticationService CreateApiKeyAuthenticationService(string authenticationSchemaName)
		{
			Debug.WriteLine(authenticationSchemaName);
			return new ApiKeyAuthenticationService(this.loggerFactory.CreateLogger<ApiKeyAuthenticationService>(), this.apiKeyRepository);
		}
	}
}
