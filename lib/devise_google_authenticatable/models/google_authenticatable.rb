require 'active_support/concern'
require 'rotp'

module Devise # :nodoc:
  module Models # :nodoc:
    module GoogleAuthenticatable
      extend ActiveSupport::Concern

      included do
        before_validation :assign_gauth_secret, :on => :create
      end

      module ClassMethods # :nodoc:
        def find_by_gauth_tmp(gauth_tmp)
          find(:first, :conditions => {:gauth_tmp => gauth_tmp})
        end

        ::Devise::Models.config(self, :ga_timeout, :ga_timedrift)
      end

      def needs_gauth?
        gauth_enabled && gauth_secret?
      end

      def get_qr
        gauth_secret
      end

      def set_gauth_enabled(param)
        update_without_password param
      end

      # Set up required fields to sign in with token.
      def assign_gauth_tmp
        self.gauth_tmp = ROTP::Base32.random_base32
        self.gauth_tmp_datetime = DateTime.now
        save

        gauth_tmp
      end

      # Reset the Gauth fields after successful authentication.
      def clear_gauth_tmp
        self.gauth_tmp = nil
        self.gauth_tmp_datetime = nil

        save
      end

      def gauth_token_expired?
        gauth_tmp_datetime.nil? ||
        gauth_tmp_datetime < self.class.ga_timeout.ago
      end

      def validate_token(token)
        return false if gauth_token_expired?

        valid_vals = []
        valid_vals << ROTP::TOTP.new(self.get_qr).at(Time.now)
        (1..self.class.ga_timedrift).each do |cc|
          valid_vals << ROTP::TOTP.new(self.get_qr).at(Time.now.ago(30*cc))
          valid_vals << ROTP::TOTP.new(self.get_qr).at(Time.now.in(30*cc))
        end

        if valid_vals.include?(token.to_i)
          clear_gauth_tmp
          return true
        end
      end

      def google_authenticator_qrcode_url
        return unless gauth_secret?

        data = Rack::Utils.escape "otpauth://totp/#{ga_username_from_email(email)}@#{Devise.http_authentication_realm || Rails.application.class.parent_name}?secret=#{gauth_secret}"

        "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=#{data}"
      end

      private

      def assign_gauth_secret
        self.gauth_secret = ROTP::Base32.random_base32
      end

      def ga_username_from_email(email)
        (/^(.*)@/).match(email)[1]
      end
    end
  end
end
