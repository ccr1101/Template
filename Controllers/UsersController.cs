using Microsoft.AspNetCore.Mvc;
using Template.Services;

namespace Template.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly ClerkService _clerkService;

        public UsersController(ClerkService clerkService)
        {
            _clerkService = clerkService;
        }

        [HttpGet("{userId}")]
        public async Task<IActionResult> GetUser(string userId)
        {
            var user = await _clerkService.GetUserAsync(userId);
            return Ok(user);
        }
    }
}
