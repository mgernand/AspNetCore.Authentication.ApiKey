namespace SampleWebApi.Repositories
{
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.ApiKey;

	/// <summary>
	///     NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
	/// </summary>
	public interface IApiKeyRepository
	{
		Task<IApiKey> GetApiKeyAsync(string key);
	}
}
