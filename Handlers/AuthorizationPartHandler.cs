using CodeSanook.Authorization.Models;
using Orchard.ContentManagement.Handlers;
using Orchard.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

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