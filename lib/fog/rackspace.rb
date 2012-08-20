require 'fog/core'

module Fog
  module Rackspace
    extend Fog::Provider

    module Errors
      class ServiceError < Fog::Errors::Error
        attr_reader :response_data

        def self.slurp(error)
          if error.response.body.empty?
            data = nil
            message = nil
          else
            data = Fog::JSON.decode(error.response.body)
            message = data['message']
          end

          new_error = super(error, message)
          new_error.instance_variable_set(:@response_data, data)
          new_error
        end
      end

      class InternalServerError < ServiceError; end
      class Conflict < ServiceError; end
      class NotFound < ServiceError; end
      class ServiceUnavailable < ServiceError; end

      class BadRequest < ServiceError
        #TODO - Need to find a bette way to print out these validation errors when they are thrown
        attr_reader :validation_errors

        def self.slurp(error)
          new_error = super(error)
          unless new_error.response_data.nil?
            new_error.instance_variable_set(:@validation_errors, new_error.response_data['validationErrors'])
          end
          new_error
        end
      end
    end

    service(:cdn,             'rackspace/cdn',            'CDN')
    service(:compute,         'rackspace/compute',        'Compute')
    service(:compute_v2,      'rackspace/compute_v2',     'Compute v2')
    service(:dns,             'rackspace/dns',            'DNS')
    service(:storage,         'rackspace/storage',        'Storage')
    service(:load_balancers,  'rackspace/load_balancers', 'LoadBalancers')
    service(:identity,        'rackspace/identity',       'Identity')
    service(:databases,       'rackspace/databases',      'Databases')

    def self.authenticate(options, connection_options = {})
      rackspace_auth_url = options[:rackspace_auth_url] || "auth.api.rackspacecloud.com"
      url = rackspace_auth_url.match(/^https?:/) ? \
        rackspace_auth_url : 'https://' + rackspace_auth_url
      uri = URI.parse(url)
      connection = Fog::Connection.new(url, false, connection_options)
      @rackspace_api_key  = options[:rackspace_api_key]
      @rackspace_username = options[:rackspace_username]
      response = connection.request({
        :expects  => [200, 204],
        :headers  => {
          'X-Auth-Key'  => @rackspace_api_key,
          'X-Auth-User' => @rackspace_username
        },
        :host     => uri.host,
        :method   => 'GET',
        :path     =>  (uri.path and not uri.path.empty?) ? uri.path : 'v1.0'
      })
      response.headers.reject do |key, value|
        !['X-Server-Management-Url', 'X-Storage-Url', 'X-CDN-Management-Url', 'X-Auth-Token'].include?(key)
      end
    end

    # Keystone Style Auth
    def self.authenticate_v2(options, connection_options = {})
      uri = URI.parse(options[:rackspace_auth_url])
      connection = Fog::Connection.new(uri.to_s, false, connection_options)
      @openstack_api_key  = options[:rackspace_api_key]
      @openstack_username = options[:rackspace_username]
      @openstack_tenant   = options[:rackspace_tenant]
      @openstack_auth_token = options[:rackspace_auth_token]
      @service_name         = "object-store" # options[:rackspace_service_name]
      @identity_service_name = options[:rackspace_identity_service_name]
      @endpoint_type         = options[:rackspace_endpoint_type] || 'publicURL'
      @openstack_region      = options[:rackspace_region]

      if @openstack_auth_token
        req_body = {
          'auth' => {
            'token' => {
              'id' => @openstack_auth_token
            }
          }
        }
      else
        req_body = {
          'auth' => {
            'passwordCredentials'  => {
              'username' => @openstack_username,
              'password' => @openstack_api_key.to_s
            }
          }
        }
      end
      req_body['auth']['tenantName'] = @openstack_tenant if @openstack_tenant

      body = retrieve_tokens_v2(connection, req_body, uri)

      svc = body['access']['serviceCatalog'].
        detect{|x| @service_name.include?(x['type']) }

      unless svc
        unless @openstack_tenant
          response = Fog::Connection.new(
            "#{uri.scheme}://#{uri.host}:#{uri.port}/v2.0/tenants", false, connection_options).request({
              :expects => [200, 204],
              :headers => {'Content-Type' => 'application/json',
                           'X-Auth-Token' => body['access']['token']['id']},
                           :host    => uri.host,
                           :method  => 'GET'
            })

            body = Fog::JSON.decode(response.body)
            if body['tenants'].empty?
              raise Errors::NotFound.new('No Tenant Found')
            else
              req_body['auth']['tenantName'] = body['tenants'].first['name']
            end
        end

        body = retrieve_tokens_v2(connection, req_body, uri)
        if body['access']['token']['tenant'].nil?
          raise Errors::NotFound.new("Invalid Tenant '#{@openstack_tenant}'")
        end
        svc = body['access']['serviceCatalog'].
          detect{|x| @service_name.include?(x['type']) }
      end

      svc['endpoints'] = svc['endpoints'].select{ |x| x['region'] == @openstack_region } if @openstack_region
      if svc['endpoints'].count > 1
        regions = svc["endpoints"].map { |x| x['region'] }.uniq.join(',')
        raise Errors::NotFound.new("Multiple regions available choose one of these '#{regions}'")
      end

      identity_svc = body['access']['serviceCatalog'].
        detect{|x| @identity_service_name.include?(x['type']) } if @identity_service_name
      tenant = body['access']['token']['tenant']
      user = body['access']['user']

      storage_url = svc['endpoints'].detect{|x| x[@endpoint_type]}[@endpoint_type].inspect

      # mgmt_url = svc['endpoints'].detect{|x| x[@endpoint_type]}[@endpoint_type]
      # identity_url = identity_svc['endpoints'].detect{|x| x['publicURL']}['publicURL'] if identity_svc

      token = body['access']['token']['id']

      {
        :user                     => user,
        :tenant                   => tenant,
        :token                    => token,
        :storage_url              => storage_url,

        # :server_management_url    => mgmt_url,
        # :identity_public_endpoint => identity_url,

        :current_user_id          => body['access']['user']['id']
      }
    end

    def self.retrieve_tokens_v2(connection, request_body, uri)
      response = connection.request({
        :expects  => [200, 204],
        :headers  => {'Content-Type' => 'application/json'},
        :body     => Fog::JSON.encode(request_body),
        :host     => uri.host,
        :method   => 'POST',
        :path     =>  (uri.path and not uri.path.empty?) ? uri.path : 'v2.0/'
      })

      Fog::JSON.decode(response.body)
    end

    # CGI.escape, but without special treatment on spaces
    def self.escape(str,extra_exclude_chars = '')
      str.gsub(/([^a-zA-Z0-9_.-#{extra_exclude_chars}]+)/) do
        '%' + $1.unpack('H2' * $1.bytesize).join('%').upcase
      end
    end
  end
end
