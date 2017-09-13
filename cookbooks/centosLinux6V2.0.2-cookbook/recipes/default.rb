#
# Cookbook Name:: centosLinux6V2.0.2-cookbook
# Recipe:: default
#
# Copyright (c) 2017 The Authors, All Rights Reserved.

mount "/tmp" do
      pass 0
      fstype "tmpfs"
      device "tmpfs"
      options "nodev,nosuid,noexec,size=256m"
      action [:enable, :mount]
end
