using Entities.DTOS.UserDTOS;
using Entities.Models.UsersModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthIdentityService.Controllers;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<User> userManager, SignInManager<User> signInManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpPost("signup")]
    public async Task<IActionResult> SignUp([FromBody] RegisterModel model)
    {
        var user = new User
        {
            UserName = model.UserName,
            Email = model.Email,
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok("User registered successfully!");
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);

        if (!result.Succeeded)
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return Unauthorized();
        }

        var roles = await _userManager.GetRolesAsync(user);
        var role = roles.FirstOrDefault();

        var token = GenerateJwtToken(user);

        var userDto = new UserDto
        {
            UserId = user.Id,
            Name = user.UserName,
            Email = user.Email,
            UserRole = role,
            Token = token
        };

        return Ok(userDto);
    }


    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok("Logged out successfully.");
    }

    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail()
    {
        try
        {
            if (!Request.Headers.TryGetValue("Authorization", out var tokenHeader) || string.IsNullOrEmpty(tokenHeader))
            {
                object res = new
                {
                    message = "Authorization token is missing.",
                    verification = false
                };

                return BadRequest(res);
            }

            var token = tokenHeader.ToString().Replace("Bearer ", string.Empty);

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

            if (jwtToken == null)
            {
                object res = new
                {
                    message = "Invalid token.",
                    verification = false
                };

                return BadRequest(res);
            }

            var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.NameId)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                object res = new
                {
                    message = "User ID not found in token.",
                    verification = false
                };

                return BadRequest(res);
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                object res = new
                {
                    message = "Invalid user ID",
                    verification = false
                };

                return BadRequest(res);
            }

            object response = new
            {
                message = "Email verified successfully!",
                verification = true
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            object response = new
            {
                message = ex.Message,
                verification = false
            };

            return BadRequest(response);
        }
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.NameId, user.Id),
            new Claim(JwtRegisteredClaimNames.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }



}
