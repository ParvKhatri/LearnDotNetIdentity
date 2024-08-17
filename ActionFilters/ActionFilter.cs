using LearnAuthenticationJWT.TokenServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace LearnAuthenticationJWT.ActionFilters
{
    // Define a custom action filter by implementing the IAsyncActionFilter interface
    public class ActionFilter : IAsyncActionFilter
    {
        private readonly ITokenService _tokenService;
        public ActionFilter(ITokenService token)
        {
            _tokenService = token;
        }
        //Implement the ONActionExecutionAsync method to add custom logic before an action execute
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var request = context.HttpContext.Request;
            //Check if the token is available and valid by calling the token service method
            if (!await _tokenService.CheckAvialableAndValidAsync(request))
            {
                //if the token is not available or not valid return an UnauthorizeResult and stop further execution
                context.Result = new UnauthorizedResult();
                return;
            }
            //If the token is valid, process to the next action in the pipeline
            await next();
        }
    }
}
