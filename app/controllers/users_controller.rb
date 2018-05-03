require 'rest-client'
require 'json'

class UsersController < ApplicationController
  before_action :set_user, only: [:show, :edit, :update, :destroy]
  # before_action :authenticate_user!, except: [:login, :callback]
  # include SecurityHelper

  def login
    @client_id = ENV['CLIENT_ID']
    @secret = ENV['CLIENT_SECRET']
  end

  def authenticated?
    session[:access_token]
  end

  def callback
    session_code = request.env['rack.request.query_hash']['code']

    # ... and POST it back to GitHub
    result = RestClient.post('https://github.com/login/oauth/access_token',
                            {:client_id => ENV['CLIENT_ID'],
                             :client_secret => ENV['CLIENT_SECRET'],
                             :code => session_code},
                             :accept => :json)

    # extract the token and granted scopes
    session[:access_token] = JSON.parse(result)['access_token']

    redirect_to :display_users
  end

  def display
    if !authenticated?
      authenticate!
    else
      access_token = session[:access_token]
      scopes = []

      begin
        auth_result = RestClient.get('https://api.github.com/user',
                                     {:params => {:access_token => access_token},
                                      :accept => :json})
      rescue => e
        # request didn't succeed because the token was revoked so we
        # invalidate the token stored in the session and render the
        # index page so that the user can start the OAuth flow again

        session[:access_token] = nil
        session[:current_user] = nil
        redirect_to :root
      end

      # the request succeeded, so we check the list of current scopes
      if auth_result.headers.include? :x_oauth_scopes
        scopes = auth_result.headers[:x_oauth_scopes].split(', ')
      end

      auth_result = JSON.parse(auth_result)

      if scopes.include? 'user:email'
        auth_result['private_emails'] =
          JSON.parse(RestClient.get('https://api.github.com/user/emails',
                         {:params => {:access_token => access_token},
                          :accept => :json}))
      end

      session[:current_user] = auth_result
    end    
  end

  def logout
    session[:access_token] = nil
    session[:current_user] = nil
    redirect_to :root
  end


  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def user_params
      params.require(:user).permit(:name, :email)
    end
end
