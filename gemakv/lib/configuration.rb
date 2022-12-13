
class Configuration
    attr_accessor :azure_tenant_id, :azure_client_id, :azure_client_secret, :azure_subscription_id, :vault_base_url, :api_version, :resource, :azure_certificate_thumbprint, :azure_certificate_private_key_file

    def initialize

        @azure_tenant_id = ENV["AZURE_VAULT_TENANT_ID"]
        @azure_client_id = ENV["AZURE_VAULT_CLIENT_ID"]
        @azure_client_secret = ENV["AZURE_VAULT_CLIENT_SECRET"]
        @azure_subscription_id = ENV["AZURE_VAULT_SUBSCRIPTION_ID"]
        @vault_base_url = ENV["AZURE_VAULT_BASE_URL"]
        @api_version = ENV["AZURE_VAULT_API_VERSION"]
        @resource = "https://vault.azure.net"
        @azure_certificate_thumbprint = nil
        @azure_certificate_private_key_file = nil        

    end

end
