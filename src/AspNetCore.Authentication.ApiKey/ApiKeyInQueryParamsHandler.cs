// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey
{
	using System.Linq;
	using System.Text.Encodings.Web;
	using System.Threading.Tasks;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.Logging;
	using Microsoft.Extensions.Options;
	using Microsoft.Extensions.Primitives;

	public class ApiKeyInQueryParamsHandler : ApiKeyHandlerBase
	{
		public ApiKeyInQueryParamsHandler(IOptionsMonitor<ApiKeyOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base(options, logger, encoder, clock)
		{
		}

		/// <inheritdoc />
		protected override Task<string> ParseApiKeyAsync()
		{
			if(this.Request.Query.TryGetValue(this.Options.KeyName, out StringValues value))
			{
				return Task.FromResult(value.FirstOrDefault());
			}

			// No ApiKey query parameter found
			return Task.FromResult(string.Empty);
		}
	}
}
