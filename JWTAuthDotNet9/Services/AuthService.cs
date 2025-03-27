using JWTAuthDotNet9.Data;
using JWTAuthDotNet9.Entities;
using JWTAuthDotNet9.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthDotNet9.Services
{
    public class AuthService(IConfiguration Configuration, UserDbContext context) : IAuthService
    {
        public async Task<string?> LoginAsync(UserDto request)
        {

            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null )
            {
                return null;
            }

            // Verify the hashed password
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return null;
            }

            // If login is successful, create a JWT token and return it
            //string token = CreateToken(user);
            return CreateToken(user);
        }

        public async Task<User?> RegisterAsync(UserDto request)
        {
            if(await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return null;
            }

            var user = new User();

            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

            // Assign username and hashed password to the static user object
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Return the user object after registration (simulated, usually you would save to a database)
            return user;
        }

        private string CreateToken(User user)
        {
            // Create a list of claims (key-value pairs representing the user's identity and roles)
            var claims = new List<Claim>
            {
                // ClaimTypes.Name: Standard claim type for a user's name/username
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            // Retrieve the secret key from configuration settings (AppSettings)
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetValue<string>("AppSettings:Token")!));

            // Create signing credentials using the secret key and the HMAC-SHA512 algorithm
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            // Create the JWT token with claims, expiration time, and signing credentials
            var tokenDescription = new JwtSecurityToken(
            issuer: Configuration.GetValue<string>("AppSettings:Issuer"),      // Token issuer (who is generating the token)
                audience: Configuration.GetValue<string>("AppSettings:Audience"),  // Intended audience of the token (who the token is meant for)
                claims: claims, // Claims list, which contains user-specific data
                expires: DateTime.Now.AddDays(1), // Expiration time (1 day)
                signingCredentials: creds // Signing credentials to validate the token
            );

            // Convert the JWT token to a string and return it and test that string using JWT.IO website
            return new JwtSecurityTokenHandler().WriteToken(tokenDescription);
        }
    }
}
