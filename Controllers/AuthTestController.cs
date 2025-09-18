using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Template.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthTestController : ControllerBase
    {
        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new
            {
                message = "API is running",
                timeStamp = DateTime.UtcNow,
                environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Unknown"
            });
        }

        [HttpGet("config")]
        public IActionResult Config()
        {
            var clerkSecretKeyExists = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CLERK_SECRET_KEY"));
            var clerkPublishableKeyExists = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CLERK_PUBLISHABLE_KEY"));

            return Ok(new {
                message = "Configuration check",
                clerkSecretKeyConfigured = clerkSecretKeyExists,
                clerkPublishableKeyConfigured = clerkPublishableKeyExists,
                clerkSecretKeyPrefix = clerkSecretKeyExists ? Environment.GetEnvironmentVariable("CLERK_SECRET_KEY")?.Substring(0, 8) + "..." : "Not set",
                clerkPublishableKeyPrefix = clerkPublishableKeyExists ? Environment.GetEnvironmentVariable("CLERK_PUBLISHABLE_KEY")?.Substring(0, 8) + "..." : "Not set"
            });
        }

        [HttpGet("public")]
        public IActionResult PublicEndpoint()
        {
            return Ok(new
            {
                message = "This endpoint should work without authentication",
                authenticated = User.Identity?.IsAuthenticated ?? false,
                timestamp = DateTime.UtcNow
            });
        }

        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            // This should be protected by middleware
            var isAuthenticated = User.Identity?.IsAuthenticated ?? false;
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var clerkUserId = User.FindFirst("clerk_user_id")?.Value;

            return Ok(new
            {
                message = "Protected endpoint accessed successfully",
                isAuthenticated = isAuthenticated,
                userId = userId,
                clerkUserId = clerkUserId,
                allClaims = User.Claims.Select(c => new { type = c.Type, value = c.Value }).ToList(),
                timestamp = DateTime.UtcNow
            });
        }

        [HttpGet("current-user")]
        public IActionResult GetCurrentUser()
        {
            // Test getting current user from token
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var clerkUserId = User.FindFirst("clerk_user_id")?.Value;

            if(string.IsNullOrWhiteSpace(userId))
            {
                return Unauthorized("No user found in token");
            }

            return Ok(new
            {
                message = "Current user extracted from token",
                userId = userId,
                clerkUserId = clerkUserId,
                canCallUsersController = !string.IsNullOrEmpty(userId),
                suggestedUsersEndpoint = $"/api/users/{userId}"
            });
        }
    }
}
