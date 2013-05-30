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

module CIMI::Collections
  class NetworkPorts < Base

    set :capability, lambda { |m| driver.respond_to? m }

    collection :network_ports do
      description 'A NetworkPort is a realized connection point between a Network'+
        ' and a resource - such as a Machine.'

      generate_show_operation :with_capability => :network_interface
      generate_index_operation :with_capability => :network_interfaces
      generate_create_operation :with_capability => :create_network_interface
      generate_delete_operation :with_capability => :destroy_network_interface

      action :start, :with_capability => :start_network_interface do
        description "Start specific NetworkPort."
        param :id,          :string,    :required
        control do
          network_port = NetworkPort.find(params[:id], self)
          action = Action.parse(self)
          network_port.perform(action) do |operation|
            no_content_with_status(202) if operation.success?
            # Handle errors using operation.failure?
          end
        end
      end

      action :stop, :with_capability => :stop_network_interface do
        description "Stop specific NetworkPort."
        param :id,          :string,    :required
        control do
          network_port = NetworkPort.find(params[:id], self)
          action = Action.parse(self)
          network_port.perform(action, self) do |operation|
            no_content_with_status(202) if operation.success?
            # Handle errors using operation.failure?
          end
        end
      end

    end

  end
end
