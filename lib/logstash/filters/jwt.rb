# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "jwt"

# This example filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::JWTFilter < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   jwt {
  #     secret => "passsupersecret"
  #   }
  # }
  #
  config_name "jwt"

  # JWT secret
  config :secret, :validate => :string
  # JWT algorithm
  config :algorithm , :validate => :string, :default => "HS256"
  # token field
  config :field, :validate => :string, :default => "token"

  # Remove token field
  config :remove_token, :validate => :boolean, :default => true

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    if event.include?(@field)
      token = event[@field]
      begin
        decoded_token = JWT.decode token, @secret, true, { :algorithm => algorithm }
        @logger.debug? && @logger.debug("Decoded token is: #{decoded_token}")
        event['[@metadata][jwt_data]'] = decoded_token.first
        event.remove(@field) if @remove_token
        filter_matched(event)
      rescue => e
        @logger.error("Invalid JWT token. exception => #{e.inspect}") if @logger
      end
    end
  end # def filter
end # class LogStash::Filters::JWTFilter
