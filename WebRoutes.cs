using Orchard.Mvc.Routes;
using Orchard.WebApi.Routes;
using System.Collections.Generic;

namespace CodeSanook.Authorization
{
    public class WebRoutes : IHttpRouteProvider
    {
        const string RouteTemplate = "authentication/{action}";

        public IEnumerable<RouteDescriptor> GetRoutes()
        {
            var route = new HttpRouteDescriptor
            {
                Name = "AuthenticationApi",
                Priority = 0,
                RouteTemplate = RouteTemplate,
                Defaults = new
                {
                    area = this.GetType().Namespace, //module name
                    controller = "Authentication" //controller name without controller subfix
                },
            };
            return new[] { route };
        }

        public void GetRoutes(ICollection<RouteDescriptor> routes)
        {
            foreach (RouteDescriptor routeDescriptor in GetRoutes())
            {
                routes.Add(routeDescriptor);
            }
        }
    }
}