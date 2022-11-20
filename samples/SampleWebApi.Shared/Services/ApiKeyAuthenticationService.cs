namespace SampleWebApi.Services
{
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.ApiKey;
	using Microsoft.Extensions.Logging;
	using SampleWebApi.Repositories;

	internal class ApiKeyAuthenticationService : IApiKeyAuthenticationService
	{
		private readonly ILogger<IApiKeyAuthenticationService> logger;
		private readonly IApiKeyRepository apiKeyRepository;

		public ApiKeyAuthenticationService(ILogger<ApiKeyAuthenticationService> logger, IApiKeyRepository apiKeyRepository)
		{
			this.logger = logger;
			this.apiKeyRepository = apiKeyRepository;
		}

		public async Task<IApiKey> AuthenticateAsync(string key)
		{
			try
			{
				return await this.apiKeyRepository.GetApiKeyAsync(key);
			}
			catch(System.Exception exception)
			{
				this.logger.LogError(exception, exception.Message);
				throw;
			}
		}
	}
}
