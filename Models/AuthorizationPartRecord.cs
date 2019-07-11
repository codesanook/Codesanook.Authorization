using Orchard.ContentManagement.Records;
using System;

namespace Codesanook.Authorization.Models
{
    public class AuthorizationPartRecord: ContentPartRecord 
    {
        public virtual Guid RefreshTokenId { get; set; }
    }
}