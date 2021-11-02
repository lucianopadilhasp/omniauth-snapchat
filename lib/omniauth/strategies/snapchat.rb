require 'omniauth/strategies/oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class Snapchat < OmniAuth::Strategies::OAuth2

      option :name, "snapchat"

      option :client_options, {
        site: 'https://adsapi.snapchat.com',
        authorize_url: 'https://accounts.snapchat.com/login/oauth2/authorize',
        token_url: 'https://accounts.snapchat.com/login/oauth2/access_token'
      }

      uid { raw_info['externalId'] }

      info do
        {
          id: raw_info['externalId'],
          name: raw_info['displayName']
        }
      end

      extra { {raw_info: raw_info} }

      def raw_info
        raw_info_url = "https://adsapi.snapchat.com/v1/me"
        @raw_info ||= access_token.get(raw_info_url).parsed
      end
      
      def raw_info
        @raw_info ||= begin
          url = 'https://kit.snapchat.com/v1/me'
          body = {query: "{ me { externalId, displayName } }"}

          access_token.post(url, body: body.to_json).parsed.dig('data', 'me')
        end
      end

      def callback_url
        options[:redirect_uri] || full_host + script_name + callback_path
      end

      def token_params
        authorization = Base64.strict_encode64("#{options.client_id}:#{options.client_secret}")
        super.merge({
          headers: {
            "Authorization" => "Basic #{authorization}"
          }
        })
      end
    end
  end
end
