// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
	using System;
	using System.Net.Http.Headers;
	using System.Text.Encodings.Web;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.Logging;
	using Microsoft.Extensions.Options;
	using Microsoft.Net.Http.Headers;

	public class ApiKeyInAuthorizationHeaderHandler : ApiKeyHandlerBase
	{
#if NET8_0_OR_GREATER
		public ApiKeyInAuthorizationHeaderHandler(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder)
			: base(options, logger, encoder)
		{
		}
#endif

#if NET6_0 || NET7_0
		public ApiKeyInAuthorizationHeaderHandler(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock systemClock)
			: base(options, logger, encoder, systemClock)
		{
		}
#endif

		/// <inheritdoc />
		protected override Task<string> ParseApiKeyAsync()
		{
			if(this.Request.Headers.ContainsKey(HeaderNames.Authorization)
			   && AuthenticationHeaderValue.TryParse(this.Request.Headers[HeaderNames.Authorization], out AuthenticationHeaderValue headerValue)
			   && (headerValue.Scheme.Equals(this.Scheme.Name, StringComparison.OrdinalIgnoreCase)
				   || headerValue.Scheme.Equals(this.Options.KeyName, StringComparison.OrdinalIgnoreCase)
			   )
			  )
			{
				return Task.FromResult(headerValue.Parameter);
			}

			// No ApiKey found
			return Task.FromResult(string.Empty);
		}
	}
}
