using Orchard.ContentManagement.Records;
using System;

namespace CodeSanook.Authorization.Models
{
    public class AuthorizationPartRecord: ContentPartRecord 
    {
        public virtual Guid RefreshTokenId { get; set; }
    }
}