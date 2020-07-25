using Orchard.ContentManagement;
using System;

namespace Codesanook.Authorization.Models
{
    public class AuthorizationPart: ContentPart<AuthorizationPartRecord>
    {
        public Guid RefreshTokenId {
            get => this.Record.RefreshTokenId;
            set => this.Record.RefreshTokenId = value;
        }
    }
}