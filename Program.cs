using Clerk.BackendAPI;
using DotNetEnv;
using Template.Options;
using Template.Middlewares;

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
builder.Services.AddSwaggerGen();

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
