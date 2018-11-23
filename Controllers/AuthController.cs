using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace webapi_jwtauthsample.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private IConfiguration _config;
        public AuthController(IConfiguration configuration)
        {
            _config = configuration;
        }

        [HttpPost("token")]
        public IActionResult Token()
        {
            //Basic Auth
            var header = Request.Headers["Authorization"];
            if (header.ToString().StartsWith("Basic"))
            {
                var credValue = header.ToString().Substring("Basic ".Length).Trim();
                var usernameAndPassenc = Encoding.UTF8.GetString(Convert.FromBase64String(credValue)); //admin:pass
                var usernameAndPass = usernameAndPassenc.Split(":");
                
                var security_key = this._config.GetSection("MyConfig").GetSection("JWTSecurityKey").Value;
                var token_expire = Int32.Parse(this._config.GetSection("MyConfig").GetSection("token_expire").Value);
                // Todo: check in DB username and pass exist
                if (usernameAndPass[0] == "Admin" && usernameAndPass[1] == "pass")
                {
                    var claimsdata = new[] { new Claim(ClaimTypes.Name, usernameAndPass[0]) };
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(security_key)); // use the security key from app setting
                    var signInCred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
                    var token = new JwtSecurityToken(
                         issuer: "JoyLin",
                         audience: "JoyLin",
                         expires: DateTime.Now.AddSeconds(token_expire),
                         claims: claimsdata,
                         notBefore: DateTime.Now,
                         signingCredentials: signInCred                                                
                        );

                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                    return Ok(tokenString);
                }
            }
            return BadRequest("wrong request");        
        }
    }
}