require "omniauth/strategies/oauth2"
require "jwt"

module OmniAuth
  module Strategies
    class MicrosoftOffice365 < OmniAuth::Strategies::OAuth2
      option :name, :microsoft_office365

      DEFAULT_SCOPE="openid User.Read Contacts.Read"

      option :client_options, {
        site:          "https://login.microsoftonline.com",
        authorize_url: "/common/oauth2/v2.0/authorize",
        token_url:     "/common/oauth2/v2.0/token"
      }

      option :authorize_options, %w[scope domain_hint]

      uid {
        raw_info['sub']
      }

      info do
        {
          name: raw_info['name'],
          nickname: raw_info['unique_name'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email'] || raw_info['upn'],
          oid: raw_info['oid'],
          tid: raw_info['tid']
        }
      end

      extra do
        {
          "raw_info" => raw_info
        }
      end

      # changed default gem
      # use JWT to parse the access token's info
      # was the only method that seemed to work when
      # requesting Exchange Active Sync endpoints
      # similar to https://github.com/marknadig/omniauth-azure-oauth2
      # (didn't use that gem because it doesn't use v2.0 endpoints)
      def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        @raw_info ||= ::JWT.decode(access_token.params.id_token, nil, false).first
      end

      def authorize_params
        super.tap do |params|
          %w[display domain_hint scope auth_type].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def avatar_file
        photo = access_token.get("https://graph.microsoft.com/v1.0/me/photo/$value")
        ext   = photo.content_type.sub("image/", "") # "image/jpeg" => "jpeg"

        Tempfile.new(["avatar", ".#{ext}"]).tap do |file|
          file.binmode
          file.write(photo.body)
          file.rewind
        end

      rescue ::OAuth2::Error => e
        if e.response.status == 404 # User has no avatar...
          return nil
        elsif e.response.status == 403 # Permissions are not allowed or the profile photo is from a local AD
          nil
        elsif e.code['code'] == 'GetUserPhoto' && e.code['message'].match('not supported')
          nil
        else
          raise
        end
      end

    end
  end
end
