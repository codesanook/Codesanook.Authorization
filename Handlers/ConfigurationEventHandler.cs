using CodeSanook.Common.DataTypes;
using CodeSanook.Configuration.Handlers;
using CodeSanook.Configuration.Models;
using Orchard;
using Orchard.ContentManagement;

namespace CodeSanook.Authorization.Handlers
{
    public class ConfigurationEventHandler : IConfigurationEventHandler
    {
        private readonly IOrchardServices orchardService;

        public ConfigurationEventHandler(IOrchardServices orchardService)
        {
            this.orchardService = orchardService;
        }

        public void OnInitialized()
        {
            //set random secret key
            var settingPart = orchardService.WorkContext.CurrentSite.As<ModuleSettingPart>();
            settingPart.RefreshTokenSecretKey = StringHelper.GetRandomAsciiString(32);
            settingPart.AccessTokenSecretKey = StringHelper.GetRandomAsciiString(32);

            settingPart.RefreshTokenExpireInDays = 30;//days
            settingPart.AccessTokenExpireInMinutes = 30;//minutes
        }
    }
}