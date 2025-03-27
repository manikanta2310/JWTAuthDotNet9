// Importing necessary namespaces
using JWTAuthDotNet9.Entities;           // This imports the 'Entities' namespace where your User model or other entities are defined.
using JWTAuthDotNet9.Model;              // This imports the 'Model' namespace which likely contains the 'UserDto' class or other data transfer objects.
using Microsoft.AspNetCore.Identity;    // Provides classes for identity management, like hashing passwords and verifying users.
using Microsoft.AspNetCore.Mvc;         // Used for defining the controller and HTTP request/response actions in ASP.NET Core MVC.
using Microsoft.IdentityModel.Tokens;   // Provides functionality to create and validate JWT tokens.
using System.IdentityModel.Tokens.Jwt;  // Provides tools to create and read JWT tokens.
using System.Security.Claims;           // Used to define claims, which are key-value pairs stored inside a JWT token (e.g., user roles, user ID).
using System.Text;                      // Provides utilities for working with text, such as converting strings to byte arrays.

namespace JWTAuthDotNet9.Controllers
{
    // The 'Route' attribute defines the base URL pattern for this controller's actions
    [Route("api/[Controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        // Static User object - This is just for the purpose of demonstration, generally a database is used to store users.
        public static User user = new();

        // Inject IConfiguration to access configuration settings like token secrets, issuer, and audience
        private readonly IConfiguration Configuration;

        // Constructor to inject the configuration
        public AuthController(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // Register user method - To handle user registration
        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            // Hash the password using PasswordHasher before storing it
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

            // Assign username and hashed password to the static user object
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            // Return the user object after registration (simulated, usually you would save to a database)
            return Ok(user);
        }

        // Login user method - To handle user login and return a JWT token if valid
        [HttpPost("login")]
        public ActionResult<string> Login(UserDto request)
        {
            // Check if the username matches the static user's username
            if (user.Username != request.Username)
            {
                return BadRequest("Invalid username");
            }

            // Verify the hashed password
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return BadRequest("Invalid password");
            }

            // If login is successful, create a JWT token and return it
            string token = CreateToken(user);
            return Ok(token);
        }

        // Method to create JWT token using user claims
        private string CreateToken(User user)
        {
            // Create a list of claims (key-value pairs representing the user's identity and roles)
            var claims = new List<Claim>
            {
                // ClaimTypes.Name: Standard claim type for a user's name/username
                new Claim(ClaimTypes.Name, user.Username)
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
