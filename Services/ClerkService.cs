using Clerk.BackendAPI;
using Clerk.BackendAPI.Models.Components;
using Microsoft.Extensions.Options;
using Template.Options;

namespace Template.Services
{
    public class ClerkService
    {
        private readonly ClerkBackendApi _sdk;

        public ClerkService(IOptions<ClerkOptions> options)
        {
            _sdk = new ClerkBackendApi(bearerAuth: options.Value.SecretKey);
        }

        public async Task<object> GetUserAsync(string userId)
        {
            var user = await _sdk.Users.GetAsync(userId);
            return user;
        }
    }
}
