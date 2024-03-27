using Microsoft.AspNetCore.Identity;

namespace IdentityManagerServerApi.Data
{
    public class AppUser : IdentityUser
    {
        public string? Name { get; set; }
    }
}
