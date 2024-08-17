using LearnAuthenticationJWT.ActionFilters;
using LearnAuthenticationJWT.DataContexts;
using LearnAuthenticationJWT.TokenServices;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//CORS Configuration
builder.Services.AddCors(Options =>
{
    Options.AddPolicy("AllowAllOrigins", builder =>
    {
        builder.AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader();
    });

});

//Database Context Cofiguration
builder.Services.AddDbContext<DataContext>(options => options.UseSqlServer(builder.Configuration["ConnectionString"]));

//Identity Configuration
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<DataContext>().AddDefaultTokenProviders();

//Controller Service
builder.Services.AddControllers();

//Swagger/OpenAPI Configuration
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Description = "Standred authorization header using the bearer scheme (\"bearer {token}\")",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });

    options.OperationFilter<SecurityRequirementsOperationFilter>();
});


// JWT Authentication Configuration
var jwtSettings = builder.Configuration.GetSection("JWT");
var Audiences = jwtSettings.GetSection("Audiences").Get<string[]>();
var issuer = jwtSettings["Issuer"];
var securityKey = jwtSettings["Token"];



builder.Services.AddAuthentication(options =>
{

    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;

}).AddJwtBearer(
    options =>
    {
        options.SaveToken = true;

        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {

            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey!)),
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidateAudience = true,
            ValidIssuer = issuer,
            ValidAudiences = Audiences,
            RequireExpirationTime = true,
        };

    });

//Authorization Configuration
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(Roles.ADMIN_ROLE));
    options.AddPolicy("AdminAndUser", policy => policy.RequireRole(Roles.USER_ROLE,Roles.ADMIN_ROLE));
 
});



// Scoped Services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<ActionFilter>();

var app = builder.Build();




// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowAllOrigins");

app.UseAuthentication();

app.UseAuthorization();

app.UseExceptionHandler("/error");
app.UseStatusCodePagesWithReExecute("/error/{0}");


// Global Exception Handling Middleware
app.Use(async (context, next) =>
{
    await next();
    if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
    {
        await context.Response.WriteAsync(" Unauthorized");
    }
});

//Custom error handling middleware for different status codes
app.Map("/error/{statusCode}", (HttpContext context) =>
{
    var statusCode = context.Request.RouteValues["statusCode"];
    var message = statusCode switch
    {
        "404" => "Page not found.", 
        "500" => "Internal server error.",
        "401" => "Unauthorized global",
        _ => "An unexpected error occurred."

    };
    return Results.Problem(detail: message, statusCode: int.Parse(statusCode.ToString()));

});
//map controller route
app.MapControllers();

app.Run();