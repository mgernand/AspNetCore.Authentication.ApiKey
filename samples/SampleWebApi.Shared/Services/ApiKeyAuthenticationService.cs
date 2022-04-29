using AspNetCore.Authentication.ApiKey;
using Microsoft.Extensions.Logging;
using SampleWebApi.Repositories;
using System.Threading.Tasks;

namespace SampleWebApi.Services
{
	internal class ApiKeyAuthenticationService : IApiKeyAuthenticationService
	{
		private readonly ILogger<IApiKeyAuthenticationService> _logger;
		private readonly IApiKeyRepository _apiKeyRepository;

		public ApiKeyAuthenticationService(ILogger<ApiKeyAuthenticationService> logger, IApiKeyRepository apiKeyRepository)
		{
			_logger = logger;
			_apiKeyRepository = apiKeyRepository;
		}

		public async Task<IApiKey> AuthenticateAsync(string key)
		{
			try
			{
				return await _apiKeyRepository.GetApiKeyAsync(key);
			}
			catch (System.Exception exception)
			{
				_logger.LogError(exception, exception.Message);
				throw;
			}
		}
	}
}