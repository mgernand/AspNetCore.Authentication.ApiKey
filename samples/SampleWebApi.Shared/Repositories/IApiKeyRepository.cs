using System.Threading.Tasks;

namespace SampleWebApi.Repositories
{
    /// <summary>
    /// NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
    /// </summary>
    public interface IApiKeyRepository
    {
        Task<MadEyeMatt.AspNetCore.Authentication.ApiKey.IApiKey> GetApiKeyAsync(string key);
    }
}