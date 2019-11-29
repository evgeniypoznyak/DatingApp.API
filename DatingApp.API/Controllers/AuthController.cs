using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repository;

        public AuthController(IAuthRepository repository)
        {
            _repository = repository;
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
    }
}