﻿using SampleWebApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SampleWebApi.Repositories
{
	/// <summary>
	/// NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
	/// </summary>
	public class InMemoryApiKeyRepository : IApiKeyRepository
	{
		private List<MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKey> _cache = new List<MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKey>
		{
			new ApiKey("Key1", "Admin"),
			new ApiKey("Key2", "User"),
		};

		public Task<MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKey> GetApiKeyAsync(string key)
		{
			var apiKey = _cache.FirstOrDefault(k => k.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
			return Task.FromResult(apiKey);
		}
	}
}
