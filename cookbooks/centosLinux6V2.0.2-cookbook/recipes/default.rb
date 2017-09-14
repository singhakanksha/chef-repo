#
# Cookbook Name:: centosLinux6V2.0.2-cookbook
# Recipe:: default
#
# Copyright (c) 2017 The Authors, All Rights Reserved.

execute 'change owner to root of /boot/grub/grub.conf' do
 command 'chown root:root /boot/grub/grub.conf'
end

execute 'change mode of /boot/grub/grub.conf' do
 command 'chmod og-rwx /boot/grub/grub.conf'
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
