using System.Web.Mvc;
using Orchard.Localization;
using Orchard;

namespace CodeSanook.Authentication.Controllers {
    public class AuthenticationController : Controller {
        public IOrchardServices Services { get; set; }

        public AuthenticationController(IOrchardServices services) {
            Services = services;
            T = NullLocalizer.Instance;
        }

        public Localizer T { get; set; }
    }
}
