class TriggerController < ApplicationController
  validate_action rebuild: { method: :post, response: :status }
  validate_action release: { method: :post, response: :status }
  validate_action runservice: { method: :post, response: :status }

  # before_action :validate_token, :set_package, :set_user, only: [:create]
  before_action :disallow_project_param, only: [:release]
  # before_action :extract_auth_from_request, :validate_auth_token, :require_valid_token, except: [:create]
  #
  # Authentication happens with tokens, so no login is required
  #
  skip_before_action :extract_user
  skip_before_action :require_login
  skip_before_action :validate_params # new gitlab versions send other data as parameters,
  # which which we may need to ignore here. Like the project hash.

  # to get access to the method release_package
  include MaintenanceHelper

  include Trigger::Errors

  def create
    authencation
    get token
    pundit
    token.call
  end

  private

  def disallow_project_param
    render_error(message: 'You specified a project, but the token defines the project/package to release', status: 403, errorcode: 'no_permission') if params[:project].present?
  end

  # AUTHENTICATION
  def extract_auth_from_request
    @token_extractor = ::TriggerControllerService::TokenExtractor.new(request).call
  end

  def validate_auth_token
    raise InvalidToken unless @token_extractor.valid?
  end

  def require_valid_token
    @token = @token_extractor.token

    raise TokenNotFound unless @token

    User.session = @token.user

    raise NoPermissionForInactive unless User.session.is_active?

    if @token.package
      @pkg = @token.package
      @pkg_name = @pkg.name
      @prj = @pkg.project
    else
      @prj = Project.get_by_name(params[:project])
      @pkg_name = params[:package] # for multibuild container
      opts = if @token.instance_of?(Token::Rebuild)
               { use_source: false,
                 follow_project_links: true,
                 follow_multibuild: true }
             else
               { use_source: true,
                 follow_project_links: false,
                 follow_multibuild: false }
             end
      @pkg = Package.get_by_project_and_name(params[:project].to_s, params[:package].to_s, opts)
    end
  end

  # AUTHORIZATION webhook
  def validate_token
    @token = Token::Service.find_by(id: params[:id])
    return if @token && @token.valid_signature?(signature, request.body.read)

    render_error message: 'Token not found or not valid.', status: 403
    false
  end

  def set_package
    @package = @token.package || Package.get_by_project_and_name(params[:project], params[:package], use_source: true)
  end

  def set_user
    @user = @token.user
  end

  # To trigger the webhook, the sender needs to
  # generate a signature with a secret token.
  # The signature needs to be generated over the
  # payload of the HTTP request and stored
  # in a HTTP header.
  # GitHub: HTTP_X_HUB_SIGNATURE
  # https://developer.github.com/webhooks/securing/
  # Pagure: HTTP_X-Pagure-Signature-256
  # https://docs.pagure.org/pagure/usage/using_webhooks.html
  # Custom signature: HTTP_X_OBS_SIGNATURE
  def signature
    request.env['HTTP_X_OBS_SIGNATURE'] ||
      request.env['HTTP_X_HUB_SIGNATURE'] ||
      request.env['HTTP_X-Pagure-Signature-256']
  end
end
