# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#

require 'rbvmomi'
require_relative './vsphere_client.rb'

module Deltacloud::Drivers::Vsphere

  MAPPER_STORAGE_ROOT = File::join("/var/tmp", "deltacloud-vsphere-#{ENV["USER"]}")

  class VsphereDriver < Deltacloud::BaseDriver

    include Deltacloud::Drivers::VSphere::Helper
    include VSphere::FileManager

    # You can use 'user_iso' feature to set 'user_iso' parameter when creating
    # a new instance where this parameter can hold gzipped CDROM iso which will
    # be mounted into created instance after boot
    feature :instances, :user_iso
    feature :instances, :user_data
    feature :instances, :user_name

    define_hardware_profile('default')

    # There is just one hardware profile where memory is measured using maximum
    # memory available on ESX for virtual machines and CPU using maximum free
    # CPU cores in ESX.
    def hardware_profiles(credentials, opts={})
      vsphere = new_client(credentials)
      safely do
        service = vsphere.serviceInstance.content
        max_memory, max_cpu_cores = [], []
        #
        # Note: Memory is being hardcoded now to range 512MB to 2GB
        #       JIRA: DTACLOUD-123
        #
        service.rootFolder.childEntity.grep(RbVmomi::VIM::Datacenter).each do |dc|
          # max_memory << dc.hostFolder.childEntity.first.summary.effectiveMemory
          max_cpu_cores << dc.hostFolder.childEntity.first.summary.numCpuCores
        end
        [Deltacloud::HardwareProfile::new('default') do
          cpu (1..max_cpu_cores.min)
          memory (512..2048)
          architecture ['x86_64', 'i386']
        end]
      end
    end

    # Configure instance state machine
    define_instance_states do
      start.to(:pending)          .on( :create )
      pending.to(:stopped)        .automatically
      stopped.to(:running)        .on( :start )
      running.to(:running)        .on( :reboot )
      running.to(:stopping)       .on( :stop )
      stopping.to(:stopped)       .automatically
      stopped.to(:finish)         .on( :destroy )
    end


    # Images are virtual machines with 'template' flag set to be true.
    # Thus we're getting them using find_vm and list_virtual_machines
    def images(credentials, opts={})
      img_arr = []
      profiles = hardware_profiles(credentials)
      # Skip traversing through all instances in all datacenters when ID
      # attribute is set
      safely do
        if opts[:id]
          template_vms = [ find_vm(credentials, opts[:id]) ].select { |vm| vm[:instance] }.compact
        else
          template_vms = list_virtual_machines(credentials).select { |vm| vm[:instance] && vm[:instance].summary.config[:template] }
        end
        img_arr = template_vms.collect do |image_hash|
          image = image_hash[:instance]
          config = image.summary.config
          # Preload all properties to save multiple SOAP calls to vSphere
          properties = {
            :name => config[:name],
            :full_name => config[:guestFullName]
          }
          image_state = convert_state(:image, image.summary.runtime[:powerState])
          # This will determine image architecture using image description.
          # Ussualy description include '64-bit' or '32-bit'. In case you used
          # some weird template/OS it will fallback to 64 bit
          image_architecture = extract_architecture(properties[:full_name]) || 'x86_64'
          Image.new(
            :id => properties[:name],
            :name => properties[:name],
            :architecture => image_architecture,
            :owner_id => credentials.user,
            :description => properties[:full_name],
            :state => image_state,
            :creation_time => image.storage[:timestamp],
            :hardware_profiles => profiles
          )
        end
      end
      img_arr = filter_on( img_arr, :architecture, opts )
      img_arr.sort_by{|e| [e.owner_id, e.name]}
    end

    def create_image(credentials, opts={})
      safely do
        find_vm(credentials, opts[:id])[:instance].MarkAsTemplate
      end
      image(credentials, :id => opts[:id])
    end

    # List all datacenters managed by the vSphere or vCenter entrypoint.
    def realms(credentials, opts={})
      vsphere = new_client(credentials)
      safely do
        if opts and opts[:id]
          datastore = find_datastore(credentials, opts[:id])
          [convert_realm(datastore)]
        else
          rootFolder = vsphere.serviceInstance.content.rootFolder
          rootFolder.childEntity.grep(RbVmomi::VIM::Datacenter).collect do |dc|
            dc.datastoreFolder.childEntity.collect { |ds| convert_realm(ds) }
          end.flatten
        end
      end
    end

    # List all running instances, across all datacenters. DeltaCloud API does
    # not yet support filtering instances by realm.
    def instances(credentials, opts={})
      inst_arr, machine_vms, pending_vms = [], [], []
      safely do
        # Using find_vm is a way faster than listing all virtual machines
        if opts[:id]
          list_vms = [ find_vm(credentials, opts[:id]) ].compact
        else
          list_vms = list_virtual_machines(credentials)
        end
        # Split machines to the 'real' one and PENDING one.
        machine_vms = list_vms.select { |vm| vm[:instance] && !vm[:instance].summary.config[:template] }
        pending_vms = list_vms.select { |vm| vm[:stored_instance] }.collect { |vm| vm[:stored_instance]}
      end
      safely do
        inst_arr = machine_vms.collect do |vm_hash|
          # Since all calls to vm are threaten as SOAP calls, reduce them using
          # local variable.
          vm, realm_id = vm_hash[:instance], vm_hash[:datastore]
          config = vm.summary.config
          next if not config
          # Template (image_id) is beeing stored as 'extraConfig' parameter in
          # instance.
          template_id = vm.config[:extraConfig].select { |k| k.key == 'template_id' }
          template_id = template_id.first.value unless template_id.empty?

          properties = {
            :memory => config[:memorySizeMB],
            :cpus => config[:numCpu],
            :storage => vm.summary.storage[:unshared],
            :name => config[:name],
            :full_name => config[:guestFullName],
          }
          instance_state = convert_state(:instance, vm.summary.runtime[:powerState])
          instance_profile = InstanceProfile::new('default',
                                                  :hwp_cpu => properties[:cpus],
                                                  :hwp_memory => properties[:memory],
                                                  :hwp_storage => properties[:storage])
          # We're getting IP address from 'vmware guest tools'.
          # If guest tools are not installed, we return list of MAC addresses
          # assigned to this instance.
          public_addresses = vm.macs.values.collect { |mac_address| InstanceAddress.new(mac_address, :type => :mac) }
          if !vm.guest[:net].empty? and ip_address = vm.guest[:net].first[:ipAddress].first
            public_addresses += [InstanceAddress.new(ip_address)]
          end
          Instance.new(
            :id => properties[:name],
            :name => properties[:name],
            :owner_id => credentials.user,
            :image_id => template_id.empty? ? nil : template_id,
            :description => properties[:full_name],
            :realm_id => realm_id,
            :state => instance_state,
            :public_addresses => public_addresses,
            :private_addresses => [],
            :instance_profile => instance_profile,
            :actions => instance_actions_for( instance_state ),
            :launch_time => vm.runtime.props[:bootTime],
            :create_image => true
          )
        end
      end
      inst_arr.compact!
      # Append 'temporary' instances to real instances.
      # 'Temporary' or 'stored' instance are used to speed up instance creation
      # process by serializing instances to datastore and map instance to task.
      #
      inst_arr += pending_vms
      filter_on( inst_arr, :state, opts )
    end


    def create_instance(credentials, image_id, opts={})
      safely do
        if opts[:hwp_cpu]
          raise "Invalid CPU value. Must be in integer format" unless valid_cpu_value?(opts[:hwp_cpu])
        end
        vm = find_vm(credentials, image_id)
        raise "ERROR: Could not find the image in given datacenter" unless vm[:instance]
        # New instance need valid resource pool and datastore to be placed.
        # For this reason, realm_id **needs** to be set.
        if opts and opts[:realm_id]
          resourcePool = find_resource_pool(credentials, opts[:realm_id])
          datastore = find_datastore(credentials, opts[:realm_id])
        else
          resourcePool = find_resource_pool(credentials, vm[:datastore])
          datastore = find_datastore(credentials, vm[:datastore])
        end
        relocate = { :pool => resourcePool, :datastore => datastore }
        relocateSpec = RbVmomi::VIM.VirtualMachineRelocateSpec(relocate)
        # Set extra configuration for VM, like template_id
        raise "ERROR: Memory must be multiple of 4" unless valid_memory_value?(opts[:hwp_memory])
        machine_config = {
          :memoryMB => opts[:hwp_memory],
          :numCPUs => opts[:hwp_cpu],
          :extraConfig => [
            { :key => 'template_id', :value => image_id },
          ]
        }
        if (opts[:user_data] and not opts[:user_data].empty?) and (opts[:user_iso] and not opts[:user_iso].empty?)
          raise "ERROR: You cannot use user_data and user_iso features together"
        end
        # If user wants to inject data into instance he need to submit a Base64
        # encoded gzipped ISO image.
        # This image will be uplaoded to the Datastore given in 'realm_id'
        # parameter and them attached to instance.
        if opts[:user_data] and not opts[:user_data].empty?
          device = vm[:instance].config.hardware.device.select { |hw| hw.class == RbVmomi::VIM::VirtualCdrom }.first
          if device
            VSphere::FileManager::user_data!(datastore, opts[:user_data], "#{opts[:name]}.iso")
            machine_config[:extraConfig] << {
              :key => 'user_data_file', :value => "#{opts[:name]}.iso"
            }
            device.connectable.startConnected = true
            device.backing = RbVmomi::VIM.VirtualCdromIsoBackingInfo(:fileName => "[#{opts[:realm_id] || vm[:datastore]}] "+
                                                                     "/#{VSphere::FileManager::DIRECTORY_PATH}/#{opts[:name]}.iso")
            machine_config.merge!({
              :deviceChange => [{
                :operation => :edit,
                :device => device
              }]
            })
          else
            raise "Failed to inject data to device because there is no CD-ROM drive defined in given template"
          end
        end
        if opts[:user_iso] and not opts[:user_iso].empty?
          device = vm[:instance].config.hardware.device.select { |hw| hw.class == RbVmomi::VIM::VirtualCdrom }.first
          if device
            VSphere::FileManager::store_iso!(datastore, opts[:user_iso], "#{opts[:name]}.iso")
            machine_config[:extraConfig] << {
              :key => 'user_iso_file', :value => "#{opts[:name]}.iso"
            }
            device.connectable.startConnected = true
            device.backing = RbVmomi::VIM.VirtualCdromIsoBackingInfo(:fileName => "[#{opts[:realm_id] || vm[:datastore]}] "+
                                                                     "/#{VSphere::FileManager::DIRECTORY_PATH}/#{opts[:name]}.iso")
            machine_config.merge!({
              :deviceChange => [{
                :operation => :edit,
                :device => device
              }]
            })
          else
            raise "Failed to inject data to device because there is no CD-ROM drive defined in given template"
          end
        end
        spec = RbVmomi::VIM.VirtualMachineCloneSpec(
          :location => relocateSpec,
          :powerOn => true,
          :template => false,
          :config => RbVmomi::VIM.VirtualMachineConfigSpec(machine_config)
        )
        instance_profile = InstanceProfile::new('default', :hwp_memory => opts[:hwp_memory], :hwp_cpu => opts[:hwp_cpu])
        task = vm[:instance].CloneVM_Task(:folder => vm[:instance].parent, :name => opts[:name] || "inst#{Time.now.to_i}", :spec => spec)
        new_instance = Instance::new(
          :id => opts[:name],
          :name => opts[:name],
          :description => opts[:name],
          :owner_id => credentials.user,
          :image_id => opts[:image_id],
          :realm_id => opts[:realm_id] || vm[:datastore],
          :state => 'PENDING',
          :public_addresses => [],
          :private_addresses => [],
          :instance_profile => instance_profile,
          :actions => instance_actions_for( 'PENDING' ),
          :create_image => false
        )
        # This will 'serialize' instance to YAML file and map it to the task.
        # Ussualy it takes like 2-3 minutes (depending on storage size) to
        # complete instance cloning process.
        map_task_to_instance(datastore, task.info.key, new_instance)
      end
    end

    # Reboot an instance, given its id.
    def reboot_instance(credentials, id)
      find_vm(credentials, id)[:instance].RebootGuest
    end

    # Start an instance, given its id.
    def start_instance(credentials, id)
      find_vm(credentials, id)[:instance].PowerOnVM_Task
    end

    # Stop an instance, given its id.
    def stop_instance(credentials, id)
      find_vm(credentials, id)[:instance].PowerOffVM_Task
    end

    # Destroy an instance, given its id. Note that this will destroy all
    # instance data.
    #
    # If there is user-data dile asocciated with instance, remove this file as
    # well.
    def destroy_instance(credentials, instance_id)
      vm = find_vm(credentials, instance_id)
      user_file = vm[:instance].config[:extraConfig].select { |k| k.key == 'user_iso_file' }.first
      VSphere::FileManager::delete_iso!(vm[:instance].send(:datastore).first, user_file.value) if user_file
      vm[:instance].Destroy_Task.wait_for_completion
    end

    alias :destroy_image :destroy_instance

    def systems(credentials, opts={})
      context = opts[:env]
      id = 'id_123'
      [
        CIMI::Model::System.new(
          :id          => context.system_url(id),
          :name        => 'Ubuntu based LAMP stack',
          :description => 'my desc',
          :machines    => { :href => context.system_machines_url(id) },
          :volumes     => { :href => context.system_volumes_url(id) },
          :networks    => { :href => context.system_networks_url(id) },
          :operations  => [
            { :href => context.system_url("#{lplatform_id}/export"), :rel => "http://schemas.dmtf.org/cimi/1/action/export" },
            { :href => context.system_url("#{lplatform_id}/start"), :rel => "http://schemas.dmtf.org/cimi/1/action/start" }
          ]
        )
      ]
    end

    def import_system(credentials, opts={})
      puts "import_system(#{opts})"
      connection_options = {
        :host => host_endpoint,
        :user => credentials.user,
        :password => credentials.password,
        :insecure => true
      }
      vim = RbVmomi::VIM.connect connection_options
      #vim.debug = true

      datacenter = vim.serviceInstance.find_datacenter
      host_folder = datacenter.hostFolder.children.first

      options = {:uri => opts[:source]}
      options[:vmName] = '' # make it default to ProductSection's product name or top-level entity ovf:id
      options[:host] = host_folder.host.first
      options[:vmFolder] = datacenter.vmFolder
      options[:resourcePool] = host_folder.resourcePool
      options[:datastore] = options[:host].datastore.first

      vim.serviceContent.ovfManager.deployOVF options
    end

    def export_system(credentials, opts={})
      puts "export_system(#{opts})"
      # hard-code for now
      vmName = 'DeltaCloud'
      datacenter = 'RORTEST Datacentre'
      destinationDir = '.'

      # export to OVF using VMware API
      vcenter_host = 'vcenter_host'
      vcenter_user = 'vcenter_user'
      vcenter_password = 'vcenter_password'
      connection_options = {
        :host     => vcenter_host,
        :user     => vcenter_user,
        :password => vcenter_password,
        :insecure => true
      }
      vim = RbVmomi::VIM.connect connection_options
      dc = vim.serviceInstance.find_datacenter(datacenter) or fail "datacenter not found"
      vm = dc.find_vm(vmName) or fail "VM not found"

      destinationDir = File.join(destinationDir, vmName)
      Dir.mkdir(destinationDir)

      # obtain lease for vm export to block other users from touching them
      lease = vm.ExportVm
      while !['done', 'error', 'ready'].member?(lease.state)
        sleep 1
      end
      if lease.state == "error"
        raise lease.error
      end
      leaseInfo = lease.info

      # from async thread, send regular updates to the lease to prevent it from aborting prematurely
      progress = 5
      keepAliveThread = Thread.new do
        while progress < 100
          lease.HttpNfcLeaseProgress(:percent => progress)
          lastKeepAlive = Time.now
          while progress < 100 && (Time.now - lastKeepAlive).to_i < (leaseInfo.leaseTimeout / 2)
            sleep 1
          end
        end
      end

      ovfFiles = leaseInfo.deviceUrl.map do |x|
        next if !x.disk
        url = x.url
        if url =~ /(https?:\/\/)\*\//
          url = url.gsub(/(https?:\/\/)(\*)\//, "\\1#{vim.host}/")
        end
        uri = URI.parse(url)

        #proxy settings:
        http_proxy = ENV['http_proxy']
        proxy_uri = URI.parse(http_proxy) if http_proxy

        if proxy_uri
          proxy_addr = proxy_uri.host
          proxy_port = proxy_uri.port
          proxy_user = proxy_uri.user
          proxy_pass = proxy_uri.password
        end

        http = Net::HTTP::Proxy(proxy_addr, proxy_port, proxy_user, proxy_pass).new(uri.host, uri.port)

        http.read_timeout = 30 * 60
        if uri.scheme == 'https'
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
        headers = {'cookie' => vim.cookie}
        localFilename = File.join(destinationDir, x.targetId)
        puts "Downloading disk to #{localFilename}"
        s = 0
        File.open(localFilename, 'w') do |fileIO|
          http.get(uri.path, headers) do |bodySegment|
            fileIO.write bodySegment
            s += bodySegment.length;
            #$stdout.write "."
            #$stdout.flush
          end
        end

        progress += 90 / leaseInfo.deviceUrl.length

        {:size => s, :deviceId => x.key, :path => x.targetId}
      end.compact

      progress = 100
      keepAliveThread.join
      lease.HttpNfcLeaseComplete()

      ovfMgr = vim.serviceContent.ovfManager
      descriptor = ovfMgr.CreateDescriptor(
        :obj => vm,
        :cdp => {:ovfFiles => ovfFiles, :includeImageFiles => false}
      )
      File.open(File.join(destinationDir, "#{vmName}.ovf"), 'w') do |io|
        io.write descriptor.ovfDescriptor
      end

      "http://cimi.example.org/ovf-packages/#{opts[:id]}" unless opts[:destination]
    end

    exceptions do

      on /InvalidLogin/ do
        status 401
      end

      on /nodename nor servname provided/ do
        status 502
      end

      on /ERROR/ do
        status 500
      end

      on /(RbVmomi::Fault|ToolsUnavailable)/ do
        status 502
      end

      on /Undefined namespace prefix/ do
        message 'VSphere Internal Error'
        status 502
      end

      on /Failed to inject data/ do
        status 502
      end

      on /Requested datastore does not exists or misconfigured/ do
        status 502
      end

      on /Connection timed out/ do
        status 504
      end

      on /execution expired/ do
        status 504
      end

      on /missing required parameter name/ do
        status 400
      end

      on /Invalid/ do
        status 400
      end

    end

    #######
    private
    #######

    def new_client(credentials)
      safely do
        RbVmomi::VIM.connect(:host => host_endpoint, :user => credentials.user, :password => credentials.password, :insecure => true)
      end
    end

    def host_endpoint
      endpoint = "#{api_provider}"
      # We need to have the 'hostname' form in API_PROVIDER, but to be
      # compatible with other drivers, we allow 'https://vsphere/api' format.
      # The 'http' and '/.*' parts are however stripped.
      if endpoint =~ /^http/
        endpoint.gsub!(/^http(s?):\/\//, '')
        endpoint.gsub!(/\/.*$/, '')
      end
      endpoint || Deltacloud::Drivers::driver_config[:vsphere][:entrypoints]['default']['default']
    end

    def convert_realm(datastore)
      if datastore.class.to_s == 'Folder'
        datastore.childEntity.collect { |datastorenew| convert_realm(datastorenew) }
      else
        Realm::new(
          :id => datastore.name,
          :name => datastore.name,
          :limit => datastore.summary.freeSpace,
          :state => datastore.summary.accessible ? 'AVAILABLE' : 'UNAVAILABLE'
        )
      end
    end

    def convert_state(object, state)
      new_state = ''
      if object == :image
        new_state = case state
          when 'poweredOff' then 'AVAILABLE'
          when 'poweredOn' then 'UNAVAILABLE'
        end
      end
      if object == :instance
        new_state = case state
          when 'poweredOff' then 'STOPPED'
          when 'poweredOn' then 'RUNNING'
          else 'PENDING'
        end
      end
      new_state
    end

    def valid_cpu_value?(val)
      true if val =~ /^(\d+)$/
    end

    def valid_memory_value?(val)
      true if (val.to_i%4) == 0
    end

  end

end
