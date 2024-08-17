# LearnDotNetIdentity
ASP.NET Core Authentication with .NET Identity and JWT
This project demonstrates how to implement authentication and authorization in an ASP.NET Core Web API using .NET Identity and JSON Web Tokens (JWT). The application supports role-based access control for different user roles (Admin, User) and includes registration, login, and token refresh functionalities.

# Table of Contents
Features
Technologies Used
Getting Started
Prerequisites
Installation
Configuration
Endpoints
Authorization
Contributing
License
Features
User Registration with AspNETCore.Identity
Role-based Authorization (Admin, User)
JWT Authentication
Token Refresh Functionality
CORS Policy for Allowing All Origins
Secure API Endpoints with Role-Based Access Control
Technologies Used
ASP.NET Core 8.0
Entity Framework Core
.NET Identity
JWT (JSON Web Tokens)
Swagger/OpenAPI for API documentation
SQL Server for database
Getting Started
Prerequisites
.NET 8 SDK
SQL Server
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
Set up the database:

Update the connection string in appsettings.json to point to your SQL Server instance.
Run the migrations to set up the database:
bash
Copy code
dotnet ef database update
Run the application:

bash
Copy code
dotnet run
Access the Swagger UI for API documentation at https://localhost:<port>/swagger.

Configuration
Update the appsettings.json file with your specific configuration settings:

ConnectionString: SQL Server connection string.
JWT:
Issuer: The token issuer (usually your app URL).
Audiences: The intended audience(s) for the token.
Token: The secret key used for signing JWT tokens, you can use any text or key.
json
Copy code
"ConnectionString": "Your_SQLServer_Connection_String",
"JWT": {
  "Issuer": "your-issuer",
  "Audiences": ["your-audience1", "your-audience2"],
  "Token": "your-secret-key"
}
Endpoints
POST /api/auth/register: Register a new user.
POST /api/auth/login: Log in and obtain a JWT.
POST /api/auth/refresh: Refresh the JWT.
POST /api/auth/register-admin: Register a new admin user.
Authorization
Admin: Has access to all endpoints.
User: Limited access based on role.
Authenticated Users: JWT is required to access secured endpoints.
Authorization policies are set up in Program.cs:

csharp
Copy code
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(Roles.ADMIN_ROLE));
    options.AddPolicy("UserOnly", policy => policy.RequireRole(Roles.USER_ROLE));
});
Contributing
Contributions are welcome! Please fork this repository, make your changes, and submit a pull request.
mail to me : parvkhatriofficial@gmail.com

License
This project is licensed under the MIT* License.