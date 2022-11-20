// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.ApiKey.Tests.Infrastructure
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Security.Claims;
	using System.Threading.Tasks;

	internal class FakeApiKeyAuthenticationService : IApiKeyAuthenticationService
	{
		public Task<IApiKey> AuthenticateAsync(string key)
		{
			IApiKey apiKey = FakeApiKeys.Keys.FirstOrDefault(k => k.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
			if(apiKey != null)
			{
				if(apiKey.Key == FakeApiKeys.FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck)
				{
					// replace the key
					apiKey = new FakeApiKey(FakeApiKeys.FakeKey, apiKey.OwnerName, apiKey.Claims);
				}
				else if(apiKey.Key == FakeApiKeys.FakeKeyThrowsNotImplemented)
				{
					throw new NotImplementedException();
				}
#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
				else if(apiKey.Key == FakeApiKeys.FakeKeyIgnoreAuthenticationIfAllowAnonymous)
				{
					throw new InvalidOperationException(nameof(ApiKeyOptions.IgnoreAuthenticationIfAllowAnonymous));
				}
#endif
			}

			return Task.FromResult(apiKey);
		}
	}

	internal class FakeApiKey : IApiKey
	{
		public FakeApiKey(string key, string ownerName, IReadOnlyCollection<Claim> claims = null)
		{
			this.Key = key;
			this.OwnerName = ownerName;
			this.Claims = claims;
		}

		public string Key { get; }

		public string OwnerName { get; }

		public IReadOnlyCollection<Claim> Claims { get; }
	}

	internal class FakeApiKeys
	{
		internal const string KeyName = "X-API-KEY";

		internal static string FakeInvalidKey = "<invalid-key>";
		internal static string FakeKey = "myrandomfakekey";
		internal static string FakeKeyThrowsNotImplemented = "myrandomfakekey-not-implemented";
		internal static string FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck = "ForLegacyIgnoreExtraValidatedApiKeyCheck";
		internal static string FakeKeyIgnoreAuthenticationIfAllowAnonymous = "IgnoreAuthenticationIfAllowAnonymous";
		internal static string FakeKeyOwner = "Fake Key";
		internal static Claim FakeNameClaim = new Claim(ClaimTypes.Name, "FakeNameClaim", ClaimValueTypes.String);
		internal static Claim FakeNameIdentifierClaim = new Claim(ClaimTypes.NameIdentifier, "FakeNameIdentifierClaim", ClaimValueTypes.String);
		internal static Claim FakeRoleClaim = new Claim(ClaimTypes.Role, "FakeRoleClaim", ClaimValueTypes.String);

		internal static List<IApiKey> Keys => new List<IApiKey>
		{
			new FakeApiKey(FakeKey, FakeKeyOwner, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim }),
			new FakeApiKey(FakeKeyThrowsNotImplemented, FakeKeyOwner, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim }),
			new FakeApiKey(FakeKeyForLegacyIgnoreExtraValidatedApiKeyCheck, FakeKeyOwner, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim }),
			new FakeApiKey(FakeKeyIgnoreAuthenticationIfAllowAnonymous, FakeKeyOwner, new List<Claim> { FakeNameClaim, FakeNameIdentifierClaim, FakeRoleClaim })
		};
	}

	internal class FakeApiKeyAuthenticationServiceFactory : IApiKeyAuthenticationServiceFactory
	{
		/// <inheritdoc />
		public IApiKeyAuthenticationService CreateApiKeyAuthenticationService(string authenticationSchemaName)
		{
			return new FakeApiKeyAuthenticationService();
		}
	}
}
