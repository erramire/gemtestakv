require 'singleton'
require 'configuration'
require 'httparty'

class Extraction
    include HTTParty
    include Singleton

    def self.initialize
        @configuration = Configuration.new
    end
    
    def self.get_value(secret_name, secret_version = nil)
        get_secret(secret_name, secret_version)
    end

    
    ### Get a Secret value from Microsoft Azure Vault
    ## secret_name: Name of the Key which contain the value
    ## secret_version (optional): Version of the key value we need, by omitting version the system to use the latest available version
    def self.get_secret(secret_name, secret_version = nil)
        # GET {vaultBaseUrl}/secrets/{secret-name}/{secret-version}?api-version=7.1
        vault_base_url  = @configuration.vault_base_url
        api_version     = @configuration.api_version
        azure_certificate_thumbprint = @configuration.azure_certificate_thumbprint

        auth_token = nil
        if azure_certificate_thumbprint.nil?
            auth_token = get_auth_token()
        else
            auth_token = get_auth_certificate_token()
        end
        puts("es es el valor del auth token")
        puts(auth_token)

        return nil if auth_token.nil?

        url = "#{vault_base_url}/secrets/#{secret_name}/#{secret_version}?api-version=#{api_version}"
        headers = { 'Authorization' => "Bearer " + auth_token }

        begin
            response = HTTParty.get(url, {headers: headers})

            puts("llego hasta aca")
            puts(url)
            puts(response)
            return response.parsed_response['value']
        rescue HTTParty::Error => e
            puts "HTTParty ERROR: #{e.message}"
            raise e
        rescue Exception => e
            puts "ERROR: #{e.message}"
            raise e               
        end
    end
    
    def self.get_auth_token
        #Microsoft identity platform and the OAuth 2.0 client credentials flow
        # https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
        # https://learn.microsoft.com/en-us/azure/active-directory/azuread-dev/v1-oauth2-client-creds-grant-flow#request-an-access-token
        
        azure_tenant_id = @configuration.azure_tenant_id
        azure_client_id = @configuration.azure_client_id
        azure_client_secret = @configuration.azure_client_secret
        resource = @configuration.resource

        authUrl = "https://login.microsoftonline.com/#{azure_tenant_id}/oauth2/token"

        data = {
            'grant_type': 'client_credentials',
            'client_id': azure_client_id,
            'client_secret': azure_client_secret,
            'resource': resource
        }

        begin

            response= HTTParty.post(authUrl, body: data)
            token = nil

            puts(response)

            if response
                #puts response.to_json
                token = response.parsed_response['access_token']
            end
            return token
        rescue HTTParty::Error => e
            puts "HTTParty ERROR: #{e.message}"
            raise e
        rescue Exception => e
            puts "ERROR: #{e.message}"
            raise e               
        end
    end
    def self.get_auth_certificate_token

        begin
            # Microsoft identity platform and the OAuth 2.0 client credentials flow
            #
            # Certificat that was upload to Azure was generated with: 
            # openssl req -x509 -newkey rsa:4096 -keyout private_key.pem -out public_certificate.pem -nodes -days 3650
            #
            # To obtain the x5t encode base64 thumbprint of the certificate: 
            # echo $(openssl x509 -in public_certificate.pem -fingerprint -noout) | sed 's/SHA1 Fingerprint=//g' | sed 's/://g' | xxd -r -ps | base64
    
            # https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
            # https://learn.microsoft.com/en-us/azure/active-directory/azuread-dev/v1-oauth2-client-creds-grant-flow#request-an-access-token
            
            azure_tenant_id = @configuration.azure_tenant_id
            azure_client_id = @configuration.azure_client_id
            resource        = @configuration.resource
            azure_certificate_thumbprint        = @configuration.azure_certificate_thumbprint
            azure_certificate_private_key_file  = @configuration.azure_certificate_private_key_file

            authUrl = "https://login.microsoftonline.com/#{azure_tenant_id}/oauth2/token"
            exp = Time.now.to_i + 4 * 3600
            nbf = Time.now.to_i - 3600
            jti = SecureRandom.uuid

            #//x5t THUMBPRINT of Cert
            header = {
                "alg": "RS256",
                "typ": "JWT",
                "x5t": azure_certificate_thumbprint
            }
            #Claim (payload)
            payload = {
                "aud": authUrl,
                "exp": exp,
                "iss": azure_client_id,
                "jti": jti,
                "nbf": nbf,
                "sub": azure_client_id
            }
                        
            token = "#{Base64.strict_encode64(header.to_json)}.#{Base64.strict_encode64(payload.to_json)}"

            # Get the private key, from the file
            azure_certificate_private_key = OpenSSL::PKey.read(File.read(azure_certificate_private_key_file))
            # The hash algorithm, I assume SHA256 is being used
            base64_signature = Base64.strict_encode64(azure_certificate_private_key.sign(OpenSSL::Digest::SHA256.new, token))

            jwt_client_assertion = "#{token}.#{base64_signature}"

            data = {
                'grant_type': 'client_credentials',
                'client_id': azure_client_id,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': jwt_client_assertion,
                'resource': resource
            }

            response = HTTParty.post(authUrl, body: data)
            token = nil

            if response
                token = response.parsed_response['access_token']
            end
            return token
        rescue HTTParty::Error => e
            puts "HTTParty ERROR: #{e.message}"
            raise e
        rescue Exception => e
            puts "ERROR: #{e.message}"
            raise e               
        end
    end        
end
