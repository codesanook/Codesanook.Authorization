using CodeSanook.Authorization.Models;
using Orchard.ContentManagement.Handlers;
using Orchard.Data;

namespace CodeSanook.Authorization.Hanlders
{
    public class AuthorizationPartHandler: ContentHandler
    {
        public AuthorizationPartHandler(IRepository<AuthorizationPartRecord> repository)
        {
            Filters.Add(StorageFilter.For(repository));
        }
    }
}