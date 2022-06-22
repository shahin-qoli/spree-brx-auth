module Devise
  module Strategies
    class TwoFactorAuthenticatable < Devise::Strategies::DatabaseAuthenticatable

      def authenticate!
        resource = mapping.to.find_for_database_authentication(authentication_hash)
        # We authenticate in two cases:
        # 1. The password and the OTP are correct
        # 2. The password is correct, and OTP is not required for login
        # We check the OTP, then defer to DatabaseAuthenticatable
        # We authenticate in two cases:
        # 1. The password and the OTP are correct
        # 2. The password is correct, and OTP is not required for login
        # We check the OTP, then defer to DatabaseAuthenticatable
        if params[scope]['otp_attempt'].empty?

        #if validate(resource) { validate_otp(resource) }
          super
        else 
          if validate(resource) { validate_otp(resource) } 
            #here we overwrote stratgey of devise

            resource  = mapping.to.find_for_database_authentication(authentication_hash)
            hashed = false

          
            remember_me(resource)
            resource.after_database_authentication
            success!(resource)
   

          # In paranoid mode, hash the password even when a resource doesn't exist for the given authentication key.
          # This is necessary to prevent enumeration attacks - e.g. the request is faster when a resource doesn't
          # exist in the database if the password hashing algorithm is not called.
            mapping.to.new.password = password if !hashed && Devise.paranoid

 
        end



        fail(Devise.paranoid ? :invalid : :not_found_in_database) unless resource

        # We want to cascade to the next strategy if this one fails,
        # but database authenticatable automatically halts on a bad password
        @halted = false if @result == :failure
      end

      def validate_otp(resource)
        return true unless resource.otp_required_for_login
        return if params[scope]['otp_attempt'].nil?
        resource.validate_and_consume_otp!(params[scope]['otp_attempt'])
      end
    end
  end
end

Warden::Strategies.add(:two_factor_authenticatable, Devise::Strategies::TwoFactorAuthenticatable)
