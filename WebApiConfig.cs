using Autofac;
using System.Web.Http;

namespace Codesanook.Authorization.Web
{
    public class WebApiConfig : Module
    {
        protected override void Load(ContainerBuilder builder)
        {
            var config = GlobalConfiguration.Configuration;
            config.Filters.Add(new AuthenticationExceptionAttribute());
        }
    }
}