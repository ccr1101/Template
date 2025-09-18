using Clerk.BackendAPI;
using DotNetEnv;
using Microsoft.OpenApi.Models;
using Template.Middlewares;
using Template.Options;

Env.Load(); 

var builder = WebApplication.CreateBuilder(args);

// Configure ClerkOptions from environment variables
builder.Services.Configure<ClerkOptions>(options =>
{
    options.SecretKey = Environment.GetEnvironmentVariable("CLERK_SECRET_KEY") ?? "";
    options.PublishableKey = Environment.GetEnvironmentVariable("CLERK_PUBLISHABLE_KEY") ?? "";
    options.AuthorizedParties = new[] { "http://localhost:3000" }; // Add your frontend URL(s)
});

// Add services to the container.
builder.Services.AddSingleton(sp => new ClerkBackendApi(bearerAuth: Environment.GetEnvironmentVariable("CLERK_SECRET_KEY")));
//builder.Services.AddSingleton(sp => new ClerkBackendApi(bearerAuth: builder.Configuration["Clerk:SecretKey"]));


builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddHttpClient();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Template API", Version = "v1" });

    // Add Bearer token support
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add Clerk authentication middleware BEFORE UseAuthorization
app.UseClerkAuth();

app.UseAuthorization();

app.MapControllers();

app.Run();
