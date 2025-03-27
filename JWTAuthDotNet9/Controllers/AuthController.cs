using JWTAuthDotNet9.Entities;
using JWTAuthDotNet9.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthDotNet9.Controllers
{

    [Route("api/[Controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        public static User user = new();

        [HttpPost("register")]
        public ActionResult<User>Register(UserDto request)
        {
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;
            return Ok(user);
        }

        [HttpPost("login")]

        public ActionResult<string> Login(UserDto request)
        {
            if(user.Username != request.Username)
            {
                return BadRequest("Invalid username");
            }
            if(new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return BadRequest("Invalid password");
            }

            string token = "Success";
            return Ok(token);
        }
    }
}
