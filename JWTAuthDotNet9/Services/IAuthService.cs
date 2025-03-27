using JWTAuthDotNet9.Entities;
using JWTAuthDotNet9.Model;

namespace JWTAuthDotNet9.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<string?> LoginAsync(UserDto request);
    }
}
