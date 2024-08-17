using LearnAuthenticationJWT.ActionFilters;
using LearnAuthenticationJWT.TokenServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LearnDotNetIdentity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[Authorize(Roles= "Admin")]
    //[Authorize(Policy= "AdminOnly")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;


        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        //[Authorize(Roles = Roles.ADMIN_ROLE)]
        [Authorize(Policy = "AdminOnly")]
        [Route("get-admin")]
        [ServiceFilter(typeof(ActionFilter))]
        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
        //[Authorize(Roles =$"{Roles.USER_ROLE},{Roles.ADMIN_ROLE}")]
        [Authorize(Policy ="AdminAndUser")]
        [ServiceFilter(typeof(ActionFilter))]
        [HttpGet]
        [Route("get-user")]
        public ActionResult GetByUser()
        {
            return Ok("Your are a user!");
        }
        [HttpGet]
        [Route("get-public")]
        public ActionResult GetByPublic()
        {
            return Ok("Your are Public!");
        }

    }
}
