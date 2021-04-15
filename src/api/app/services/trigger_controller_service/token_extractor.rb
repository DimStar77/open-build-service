module TriggerControllerService
  class TokenExtractor
    def initialize(http_request)
      @http_request = http_request
    end

    def call
      extract_auth_token
      self
    end

    def extract_auth_token
      events = ['Push Hook', 'Tag Push Hook', 'Merge Request Hook']
      @auth_token = if events.any?(@http_request.env['HTTP_X_GITLAB_EVENT'])
                      'Token ' + @http_request.env['HTTP_X_GITLAB_TOKEN']
                    else
                      # This is for osc, GitHub is signing the body with the token
                      @http_request.env['HTTP_AUTHORIZATION']
                    end
    end

    def valid?
      @auth_token.present? && @auth_token[0..4] == 'Token' && @auth_token[6..-1].match?(%r{^[A-Za-z0-9+/]+$})
    end

    # it will return a Token subclass or raise ActiveRecord::RecordNotFound
    def token
      Token.token_type(@http_request['action']).find_by_string!(@auth_token[6..-1])
    end

    # from Token::Service
    def valid_signature?(signature, body)
      return false unless signature

      ActiveSupport::SecurityUtils.secure_compare(signature_of(body), signature)
    end

    # from Token::Service
    def signature_of(body)
      # TODO: use sha256 (from X-Hub-Signature-256)
      'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), string, body)
    end
  end
end
