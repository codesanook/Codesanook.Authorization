using Codesanook.Authorization.Models;
using Orchard.ContentManagement;
using Orchard.ContentManagement.Handlers;
using Orchard.Localization;

namespace Codesanook.Common.Handlers {
    public class AuthorizationSettingPartHandler : ContentHandler {
        private const string groupId = "Authorization settings";

        public Localizer T { get; set; }

        public AuthorizationSettingPartHandler() {
            T = NullLocalizer.Instance;

            // Attach a part to the content item Site
            Filters.Add(new ActivatingFilter<AuthorizationSettingPart>("Site"));

            // Set a view for a content part 
            Filters.Add(new TemplateFilterForPart<AuthorizationSettingPart>(
               prefix: "AuthorizationSetting",
               templateName: "Parts/AuthorizationSetting", // Part in EditorTemplates
               groupId: groupId // Same value as a parameter of GroupInfo but ignore case
            ));
        }

        protected override void GetItemMetadata(GetContentItemMetadataContext context) {
            if (context.ContentItem.ContentType != "Site") {
                return;
            }

            base.GetItemMetadata(context);
            context.Metadata.EditorGroupInfo.Add(new GroupInfo(T(groupId)));
        }
    }
}
