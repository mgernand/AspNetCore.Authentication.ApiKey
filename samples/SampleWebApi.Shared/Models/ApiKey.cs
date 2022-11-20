namespace SampleWebApi.Models
{
	using System.Collections.Generic;
	using System.Security.Claims;
	using MadEyeMatt.AspNetCore.Authentication.ApiKey;

	internal class ApiKey : IApiKey
	{
		public ApiKey(string key, string owner, List<Claim> claims = null)
		{
			this.Key = key;
			this.OwnerName = owner;
			this.Claims = claims ?? new List<Claim>();
		}

		public string Key { get; }
		public string OwnerName { get; }
		public IReadOnlyCollection<Claim> Claims { get; }
	}
}
