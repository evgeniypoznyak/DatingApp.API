using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repository;
        private readonly IConfiguration _configuration;

        public AuthController(IAuthRepository repository, IConfiguration configuration)
        {
            _repository = repository;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            // validating request happening in DTO while casting from POST request by [APIController]
            // all validating error taking care by [APIController]

            userForRegisterDto.UserName = userForRegisterDto.UserName.ToLower();

            if (await _repository.UserExist(userForRegisterDto.UserName)) return BadRequest("Username already exist");

            var userToCreate = new User
            {
                UserName = userForRegisterDto.UserName,
            };

            var createUser = await _repository.Register(userToCreate, userForRegisterDto.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFromRepository =
                await _repository.Login(userForLoginDto.UserName.ToLower(), userForLoginDto.Password);
            if (userFromRepository == null) return Unauthorized();

            var (tokenHandler, token) = GetTokenAndTokenHandler(userFromRepository);
            
            return Ok(new
            {
                token = tokenHandler.WriteToken(token)
            });
        }

        public Tuple<JwtSecurityTokenHandler, SecurityToken> GetTokenAndTokenHandler(User userFromRepository)
        {
//            var claims = new[]
//            {
//                new Claim(ClaimTypes.NameIdentifier, userFromRepository.Id.ToString()),
//                new Claim(ClaimTypes.Name, userFromRepository.UserName),
//            };

            var securityKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value)
            );

            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);

            // start creating token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userFromRepository.Id.ToString()),
                    new Claim(ClaimTypes.Name, userFromRepository.UserName),
                }),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = signingCredentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);
            
            return new Tuple<JwtSecurityTokenHandler, SecurityToken>(tokenHandler, token);
        }
    }
}