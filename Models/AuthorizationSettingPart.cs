using Orchard.ContentManagement;

namespace Codesanook.Authorization.Models {
    public class AuthorizationSettingPart : ContentPart {

        public string RefreshTokenSecretKey {
            get => this.Retrieve(x => x.RefreshTokenSecretKey);
            set => this.Store(x => x.RefreshTokenSecretKey, value);
        }

        public string AccessTokenSecretKey {
            get => this.Retrieve(x => x.AccessTokenSecretKey);
            set => this.Store(x => x.AccessTokenSecretKey, value);
        }

        public int RefreshTokenExpireInDays {
            get => this.Retrieve(x => x.RefreshTokenExpireInDays);
            set => this.Store(x => x.RefreshTokenExpireInDays, value);
        }

        public int AccessTokenExpireInMinutes {
            get => this.Retrieve(x => x.AccessTokenExpireInMinutes);
            set => this.Store(x => x.AccessTokenExpireInMinutes, value);
        }

        public string UnverifiedEmailErrorMessageTemplate {
            get => this.Retrieve(x => x.UnverifiedEmailErrorMessageTemplate);
            set => this.Store(x => x.UnverifiedEmailErrorMessageTemplate, value);
        }

        public string UnactivatedErrorMesageTemplate {
            get => this.Retrieve(x => x.UnactivatedErrorMesageTemplate);
            set => this.Store(x => x.UnactivatedErrorMesageTemplate, value);
        }
    }
}