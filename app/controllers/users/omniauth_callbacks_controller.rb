class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
    p "====================="
    def openid_connect
        p "====================="
        @user = User.from_omniauth(request.env["omniauth.auth"])
        if @user.persisted?
            sign_in_and_redirect @user, event: :authentication
            set_flash_message(:notice, :success, kind: "OpenID Connect") if is_navigational_format?
        else
            session["devise.openid_connect_data"] = request.env["omniauth.auth"]
            redirect_to new_user_registration_url
        end
    end
end