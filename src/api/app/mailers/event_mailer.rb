class EventMailer < ActionMailer::Base

  def set_headers
    @host = ::Configuration.first.obs_url
    @configuration = ::Configuration.first

    headers['Precedence'] = 'bulk'
    headers['X-Mailer'] = 'OBS Notification System'
    headers['X-OBS-URL'] = ActionDispatch::Http::URL.url_for(controller: :main, action: :index, only_path: false, host: @host)
    headers['Auto-Submitted'] = 'auto-generated'
  end

  def event(user, e)
    set_headers
    @e = e.expanded_payload

    headers(e.custom_headers)

    template_name = e.template_name
    orig = e.originator
    to = user.email
    # no need to tell user about this own actions
    # TODO: make configurable?
    return if orig == to
    mail(to: to,
         subject: e.subject,
         reply_to: orig,
         from: e.mail_sender,
         template_name: template_name)
  end

end
