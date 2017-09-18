#
# Cookbook Name:: centosLinux6V2.0.2-cookbook
# Recipe:: default
#
# Copyright (c) 2017 The Authors, All Rights Reserved.

#execute 'change owner to root of /boot/grub/grub.conf' do
# command 'chown root:root /boot/grub/grub.conf'
#end

#execute 'change mode of /boot/grub/grub.conf' do
# command 'chmod og-rwx /boot/grub/grub.conf'
#end

#file '/etc/sysconfig/init' do
# content 'PROMPT=no'
#end

%w[ /etc /etc/dconf /etc/dconf/profile ].each do |path|
  directory path do
    action :create
  end
end

file '/etc/dconf/profile/gdm' do
 content "user-db:user\nsystem-db:gdm file-db:/usr/share/gdm/greeter-dconf-defaults"
end


file '/etc/selinux/config' do
 content 'SELINUX=enforcing'
end

file '/etc/selinux/config' do
 content 'SELINUXTYPE=targeted'
end

file '/etc/motd' do
  mode '0644'
  owner 'root'
  group 'root'
end

file '/etc/issue' do
  mode '0644'
  owner 'root'
  group 'root'
end

file '/etc/issue.net' do
  mode '0644'
  owner 'root'
  group 'root'
end

ruby_block "insert_line1" do
 block do
  file = Chef::Util::FileEdit.new("/etc/selinux/config")
  file.insert_line_if_no_match("SELINUX=enforcing","SELINUX=enforcing")
  file.insert_line_if_no_match("SELINUXTYPE=targeted","SELINUXTYPE=targeted")
 end
end

ruby_block "insert_line2" do
  block do
    file = Chef::Util::FileEdit.new("/etc/sysconfig/init")
    file.insert_line_after_match("PROMPT=yes", "PROMPT=no")
    file.insert_line_after_match("SINGLE=/sbin/sushell","SINGLE=/sbin/sulogin") 
    file.write_file
  end
end

execute 'gpg-key install' do
  command 'rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6'
end

execute 'AIDE install' do
 command 'yum install -y aide'
end

execute 'AIDE initialize' do
 command 'aide --init'
end

execute 'move' do
 command('mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz')
end
