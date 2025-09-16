using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace Template.Middlewares
{
    public class ClerkJwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;

        public ClerkJwtMiddleware(RequestDelegate next, IConfiguration configuration, HttpClient httpClient)
        {
            _next = next;
            _configuration = configuration;
            _httpClient = httpClient;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Bypass for public routes
            var path = context.Request.Path.Value ?? "";
            if (path.StartsWith("/health") || path.StartsWith("/swagger") || path.StartsWith("/api/webhooks"))
            {
                await _next(context);
                return;
            }

            // Get the token from Authorization header
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Missing or invalid authorization header");
                return;
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();

            try
            {
                // Validate the JWT token
                var clerkPublishableKey = Environment.GetEnvironmentVariable("CLERK_PUBLISHABLE_KEY");
                if (string.IsNullOrEmpty(clerkPublishableKey))
                {
                    throw new InvalidOperationException("CLERK_PUBLISHABLE_KEY not configured");
                }

                // Extract instance ID from publishable key (pk_test_xxx or pk_live_xxx)
                var instanceId = ExtractInstanceId(clerkPublishableKey);

                // Get JWKS from Clerk
                var jwksUrl = $"https://{instanceId}.clerk.accounts.dev/.well-known/jwks.json";
                var jwksJson = await _httpClient.GetStringAsync(jwksUrl);
                var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(jwksJson);

                // Validate token
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = jwks?.Keys,
                    ValidateIssuer = true,
                    ValidIssuer = $"https://{instanceId}.clerk.accounts.dev",
                    ValidateAudience = false, // Clerk doesn't typically use audience validation
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                // Extract user ID from token claims
                var userId = principal.FindFirst("sub")?.Value;
                if (!string.IsNullOrEmpty(userId))
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, userId),
                        new Claim("clerk_user_id", userId)
                    };

                    // Add any other claims from the token
                    claims.AddRange(principal.Claims);

                    var identity = new ClaimsIdentity(claims, "Clerk");
                    context.User = new ClaimsPrincipal(identity);
                }

                await _next(context);
            }
            catch (Exception ex)
            {
                // Log the exception for debugging
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync($"Authentication failed: {ex.Message}");
            }
        }

        private static string ExtractInstanceId(string publishableKey)
        {
            // Extract instance ID from pk_test_xxx or pk_live_xxx format
            var parts = publishableKey.Split('_');
            if (parts.Length >= 3)
            {
                return string.Join("_", parts.Skip(2));
            }
            throw new ArgumentException("Invalid publishable key format");
        }
    }

    public static class ClerkJwtMiddlewareExtensions
    {
        public static IApplicationBuilder UseClerkAuth(this IApplicationBuilder app) =>
            app.UseMiddleware<ClerkJwtMiddleware>();
    }
}