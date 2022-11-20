using Microsoft.Extensions.Logging;
using SampleWebApi.Repositories;
using System.Threading.Tasks;

namespace SampleWebApi.Services
{
	internal class ApiKeyAuthenticationService : MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKeyAuthenticationService
	{
		private readonly ILogger<MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKeyAuthenticationService> _logger;
		private readonly IApiKeyRepository _apiKeyRepository;

		public ApiKeyAuthenticationService(ILogger<ApiKeyAuthenticationService> logger, IApiKeyRepository apiKeyRepository)
		{
			_logger = logger;
			_apiKeyRepository = apiKeyRepository;
		}

		public async Task<MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKey> AuthenticateAsync(string key)
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