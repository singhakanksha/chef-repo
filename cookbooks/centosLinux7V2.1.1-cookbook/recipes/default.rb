#
# Cookbook Name:: centosLinux7V2.1.1-cookbook
# Recipe:: default
#
# Copyright (c) 2017 The Authors, All Rights Reserved.
execute 'gpg-key install' do
  command 'rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7'
end
