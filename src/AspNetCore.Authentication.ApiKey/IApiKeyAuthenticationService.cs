// Copyright (c) Mihir Dilip, Matthias Gernand. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

using System.Threading.Tasks;

namespace AspNetCore.Authentication.ApiKey
{
	/// <summary>
	/// Implementation of this interface will be used by the 'ApiKey' authentication handler to validated and get details from the key.
	/// </summary>
	public interface IApiKeyAuthenticationService
	{
		/// <summary>
		/// Authenticates the API key and returns an instance of <see cref="IApiKey"/> if successful.
		/// </summary>
		/// <param name="apiKey"></param>
		/// <returns></returns>
		Task<IApiKey> AuthenticateAsync(string apiKey);
	}
}
