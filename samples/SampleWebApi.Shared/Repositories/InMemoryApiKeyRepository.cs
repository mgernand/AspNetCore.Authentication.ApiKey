namespace SampleWebApi.Repositories
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.ApiKey;
	using SampleWebApi.Models;

	/// <summary>
	///     NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
	/// </summary>
	public class InMemoryApiKeyRepository : IApiKeyRepository
	{
		private readonly List<IApiKey> cache = new List<IApiKey>
		{
			new ApiKey("Key1", "Admin"),
			new ApiKey("Key2", "User")
		};

		public Task<IApiKey> GetApiKeyAsync(string key)
		{
			IApiKey apiKey = this.cache.FirstOrDefault(k => k.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
			return Task.FromResult(apiKey);
		}
	}
}
