// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
	using System;
	using System.Linq;
	using System.Net.Http.Headers;
	using System.Text.Encodings.Web;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.Logging;
	using Microsoft.Extensions.Options;
	using Microsoft.Extensions.Primitives;
	using Microsoft.Net.Http.Headers;

	public class ApiKeyInHeaderOrQueryParamsHandler : ApiKeyHandlerBase
	{
#if NET8_0_OR_GREATER
		public ApiKeyInHeaderOrQueryParamsHandler(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder)
			: base(options, logger, encoder)
		{
		}
#endif

#if NET6_0 || NET7_0
		public ApiKeyInHeaderOrQueryParamsHandler(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock systemClock)
			: base(options, logger, encoder, systemClock)
		{
		}
#endif

		/// <inheritdoc />
		protected override Task<string> ParseApiKeyAsync()
		{
			// Try query parameter
			if(this.Request.Query.TryGetValue(this.Options.KeyName, out StringValues value))
			{
				return Task.FromResult(value.FirstOrDefault());
			}

			// No ApiKey query parameter found try headers
			if(this.Request.Headers.TryGetValue(this.Options.KeyName, out StringValues headerValue))
			{
				return Task.FromResult(headerValue.FirstOrDefault());
			}

			// No ApiKey query parameter or header found then try Authorization header
			if(this.Request.Headers.ContainsKey(HeaderNames.Authorization)
			   && AuthenticationHeaderValue.TryParse(this.Request.Headers[HeaderNames.Authorization], out AuthenticationHeaderValue authHeaderValue)
			   && authHeaderValue.Scheme.Equals(this.Options.KeyName, StringComparison.OrdinalIgnoreCase)
			  )
			{
				return Task.FromResult(authHeaderValue.Parameter);
			}

			// No ApiKey found
			return Task.FromResult(string.Empty);
		}
	}
}
