using CodeSanook.Authorization.Models;
using Orchard.ContentManagement.MetaData;
using Orchard.Core.Contents.Extensions;
using Orchard.Data;
using Orchard.Data.Migration;
using System;
using CodeSanook.Common.Data;
using Orchard;
using Orchard.ContentManagement;
using CodeSanook.Configuration.Models;
using CodeSanook.Common.DataTypes;
using Orchard.Users.Models;
using CodeSanook.Common.Models;

namespace CodeSanook.Authorization
{
    public class Migrations : DataMigrationImpl
    {
        private readonly IOrchardServices orchardService;

        public Migrations(IOrchardServices orchardService, ITransactionManager transactionManager)
        {
            this.orchardService = orchardService;
        }

        public int Create()
        {
            //create table
            SchemaBuilder.CreateTable<AuthorizationPartRecord>(table => table
                .ContentPartRecord()
                .Column<AuthorizationPartRecord, Guid>(record => record.RefreshTokenId)
            );

            //attach to user content type
            ContentDefinitionManager
                .AlterPartDefinition(nameof(AuthorizationPart), build => build.Attachable(true));

            ContentDefinitionManager
                .AlterTypeDefinition<UserPart>(builder => builder.WithPart(nameof(AuthorizationPart)));

            //set random secret key
            var settingPart = orchardService.WorkContext.CurrentSite.As<ModuleSettingPart>();
            settingPart.RefreshTokenSecretKey = StringHelper.GetRandomAsciiString(32);
            settingPart.AccessTokenSecretKey = StringHelper.GetRandomAsciiString(32);

            settingPart.RefreshTokenExpireInDays = 30;//days
            settingPart.AccessTokenExpireInMinutes = 30;//minutes
            return 1;
        }
    }
}