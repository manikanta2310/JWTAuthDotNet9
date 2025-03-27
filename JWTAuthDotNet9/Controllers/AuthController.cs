using JWTAuthDotNet9.Entities;
using JWTAuthDotNet9.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthDotNet9.Controllers
{

    [Route("api/[Controller]")]
    [ApiController]
    public class AuthController(IConfiguration Configuration) : Controller
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

            string token = Createtoken(user);
            return Ok(token);
        }

        // Generating JWT token using claims 
        private string Createtoken(User user)
        {
            var claims = new List<Claim>
            {
                // name identifier usuallly is used for the actual ID of the user
                new Claim(ClaimTypes.Name, user.Username)
            };
            // need to add a secret key to sign the token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetValue<string>("AppSettings:Token")!));

            // need to add the key to the signing credentials
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescription = new JwtSecurityToken(
                issuer: Configuration.GetValue<string>("AppSettings:Issuer"),
                audience: Configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescription);
        }


    }
}
