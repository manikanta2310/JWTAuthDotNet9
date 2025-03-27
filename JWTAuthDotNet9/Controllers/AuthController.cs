// Importing necessary namespaces
using JWTAuthDotNet9.Entities;           // This imports the 'Entities' namespace where your User model or other entities are defined.
using JWTAuthDotNet9.Model;              // This imports the 'Model' namespace which likely contains the 'UserDto' class or other data transfer objects.
using JWTAuthDotNet9.Services;
using Microsoft.AspNetCore.Authorization;
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
    public class AuthController(IAuthService authService) : Controller
    {
    
        [HttpPost("register")]
        public  async Task<ActionResult<User>>Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
            {
                return BadRequest("Invalid username or already exists");
            }
            return Ok(user);


        }

        // Login user method - To handle user login and return a JWT token if valid
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
            if (token is null)
            {
                return BadRequest("Invalid username or password");
            }
            return Ok(token);

        }
        [Authorize]
        [HttpGet]
        public IActionResult AuthenticationOnlyEndpoint()
        {
            return Ok("You are authenticated!!!!!!!!!");
        }



    }
}
