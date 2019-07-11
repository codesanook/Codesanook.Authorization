using Codesanook.Authorization.Models;
using Orchard.ContentManagement.MetaData;
using Orchard.Core.Contents.Extensions;
using Orchard.Data;
using Orchard.Data.Migration;
using System;
using Codesanook.Common.Data;
using Orchard;
using Orchard.ContentManagement;
using Codesanook.Configuration.Models;
using Codesanook.Common.DataTypes;
using Orchard.Users.Models;
using Codesanook.Common.Models;

namespace Codesanook.Authorization
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

            return 1;
        }
    }
}