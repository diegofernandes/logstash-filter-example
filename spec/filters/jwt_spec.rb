# encoding: utf-8
require "spec_helper"
require "logstash/filters/jwt"
require "jwt"

describe LogStash::Filters::JWTFilter do
  describe "JWT valid" do
    secret = "test";
    algorithm = 'HS256'
    payload = {:data => 'test'}
    token = JWT.encode payload, secret, algorithm
    let(:config) do <<-CONFIG
      filter {
        jwt {
          secret => "#{secret}"
          algorithm => "#{algorithm}"
          field => "token"
        }
      }
    CONFIG
    end

    sample("token" => "#{token}") do
      expect(subject["[@metadata][jwt_data]"]).to_not be_nil
      expect(subject["[token]"]).to be_nil
      expect(subject["[@metadata][jwt_data][data]"]).to eq('test')
    end
  end
  describe "JWT invalid" do
    secret = "test";
    algorithm = 'HS256'
    payload = {:data => 'test'}
    token = JWT.encode payload, secret, algorithm
    let(:config) do <<-CONFIG
      filter {
        jwt {
          secret => "foo"
          algorithm => "#{algorithm}"
          field => "token"
        }
      }
    CONFIG
    end
    sample("token" => "#{token}") do
      expect(subject["[@metadata][jwt_data]"]).to be_nil
    end
  end
end
