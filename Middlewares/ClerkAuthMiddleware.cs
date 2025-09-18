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

            // List of paths that should bypass authentication
            var publicPaths = new[]
            {
                "/health",
                "/swagger",
                "/api/authtest/health",    // FIXED: lowercase 'authtest'
                "/api/authtest/config",    // ADDED: config endpoint
                "/api/authtest/public",    // ADDED: public endpoint
                "/api/webhooks"
            };
            // IMPROVED: Better path matching logic
            var shouldBypass = publicPaths.Any(publicPath =>
                path.StartsWith(publicPath, StringComparison.OrdinalIgnoreCase)) ||
                path.Contains("swagger", StringComparison.OrdinalIgnoreCase);

            if (shouldBypass)
            {
                await _next(context);
                return;
            }

            // Get the token from Authorization header
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("Missing or invalid authorization header");
                return;
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();

            try
            {
                // ADDED: First decode token to get issuer (more reliable than extracting from key)
                var handler = new JwtSecurityTokenHandler();
                if (!handler.CanReadToken(token))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\": \"Invalid token format\"}");
                    return;
                }

                var jsonToken = handler.ReadJwtToken(token);
                var issuer = jsonToken.Issuer;

                // IMPROVED: Use issuer from token instead of constructing from publishable key
                string jwksUrl;
                if (!string.IsNullOrEmpty(issuer))
                {
                    jwksUrl = $"{issuer.TrimEnd('/')}/.well-known/jwks.json";
                }
                else
                {
                    // Fallback: construct from publishable key
                    var clerkPublishableKey = Environment.GetEnvironmentVariable("CLERK_PUBLISHABLE_KEY");
                    if (string.IsNullOrEmpty(clerkPublishableKey))
                    {
                        throw new InvalidOperationException("CLERK_PUBLISHABLE_KEY not configured");
                    }
                    var instanceId = ExtractInstanceId(clerkPublishableKey);
                    jwksUrl = $"https://{instanceId}.clerk.accounts.dev/.well-known/jwks.json";
                }

                // IMPROVED: Better error handling for JWKS fetch
                var response = await _httpClient.GetAsync(jwksUrl);
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    throw new HttpRequestException($"JWKS fetch failed: {response.StatusCode} - {errorContent}");
                }

                var jwksJson = await response.Content.ReadAsStringAsync();
                var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(jwksJson);

                // Validate token
                var tokenHandler = new JwtSecurityTokenHandler
                {                                               //by default, JwtSecurityTokenHandler maps claim types into .NET’s ClaimTypes
                    MapInboundClaims = false                   //disable the default claim mapping
                };
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = jwks?.Keys,
                    ValidateIssuer = true,
                    ValidIssuer = issuer, // FIXED: Use actual issuer from token
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                // Extract user ID from token claims
                var userId = principal.FindFirst("sub")?.Value
                    ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (!string.IsNullOrEmpty(userId))
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, userId),
                        new Claim("clerk_user_id", userId)
                    };

                    // IMPROVED: Don't duplicate claims
                    foreach (var claim in principal.Claims)
                    {
                        if (claim.Type != "sub") // Don't duplicate the subject claim
                        {
                            claims.Add(new Claim(claim.Type, claim.Value));
                        }
                    }

                    var identity = new ClaimsIdentity(claims, "Clerk");
                    context.User = new ClaimsPrincipal(identity);
                }

                await _next(context);
            }
            catch (Exception ex)
            {
                // IMPROVED: Better error response format
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync($"{{\"error\": \"Authentication failed: {ex.Message}\"}}");
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