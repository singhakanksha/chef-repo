# # encoding: utf-8

# Inspec test for recipe centosLinux6V2.0.2-cookbook::default

# The Inspec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec_reference.html

control "cis-1-1-1" do
 impact 1.1
 title "Ensure mounting of cramfs filesystems is disabled (Scored)"
 desc "Most packages managers implement GPG key signing to verify Removing support for unneeded filesystem types reduces the local attack surface of the server. If this filesystem type is not needed, disable it.
 package integrity during installation."
 describe kernel_module("cramfs") do
   it { should_not be_loaded}
 end
end

control "cis-1-1-2" do
 impact 1.1
 title "Ensure mounting of freevxfs filesystems is disabled (Scored)"
 desc "Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it." 
 describe kernel_module("freevxfs") do
   it { should_not be_loaded}
 end
end

control "cis-1-1-3" do
 impact 1.1
 title "Ensure mounting of jffs2 filesystems is disabled (Scored)" 
 desc "Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
 describe kernel_module("jffs2") do
   it { should_not be_loaded}
 end
end

control "cis-1-1-4" do
 impact 1.1
 title "Ensure mounting of hfs filesystems is disabled (Scored)"
 desc "The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems."
 describe kernel_module("hfs") do
   it { should_not be_loaded}
 end
end

control "cis-1-1-1-5" do
 impact 1.1
 title "Ensure mounting of hfsplus filesystems is disabled (Scored)"
 desc "The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows you to mount Mac OS filesystems."
 describe kernel_module("hfsplus") do
   it { should_not be_loaded}
 end
end


control "cis-1-1-1-6" do
 impact 1.1
 title "Ensure mounting of squashfs filesystems is disabled (Scored)"
 desc "The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs ). A squashfs image can be used without having to first decompress the image."
 describe kernel_module("squashfs") do
   it { should_not be_loaded}
 end
end


control "cis-1-1-1-7" do
 impact 1.1
 title "Ensure mounting of udf filesystems is disabled (Scored)"
 desc "The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats."
 describe kernel_module("udf") do
   it { should_not be_loaded}
 end
end

control "cis-1-1-1-8" do
 impact 1.1
 title "Ensure mounting of FAT filesystems is disabled (Scored)
"
 desc "The FAT filesystem format is primarily used on older windows systems and portable USB drives or flash modules. It comes in three types FAT12 , FAT16 , and FAT32 all of which are supported by the vfat kernel module."
 describe kernel_module("vfat") do
   it { should_not be_loaded}
 end
end


control "cis-1-2-1" do
 impact 1.1
 title "Ensure package manager repositories are configured (Not Scored)"
 desc "If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software."
 describe command("yum repolist") do
  its('stdout') {should match /repolist: 7,362/}
 end
end

control "cis-1-2-2" do 
 impact 1.1
 title "Ensure GPG keys are configured (Not Scored)"
 desc "It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system."
 describe command("rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'") do
 its('stdout') {should match /CentOS 6 Official Signing Key/} 
 end
end

control "cis-1-2-3" do
 impact 1.1
 title "Ensure gpgcheck is globally activated (Scored)"
 desc "It is important to ensure that an RPM's package signature is always checked prior to installation to ensure that the software is obtained from a trusted source."
 describe file('/etc/yum.conf') do
 its('content') {should match /gpgcheck=1/}
 end
 describe command('grep ^gpgcheck /etc/yum.repos.d/*') do
 its('stdout') {should match /gpgcheck=1/}
 end
end

control "cis-1-3-1" do
 impact 1.1
 title "Ensure AIDE is installed (Scored)"
 desc "By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries."
 describe command("rpm -q aide") do
 its('stdout') { should match /aide-/}
 end
end

#control "cis-1-4-1" do
# impact 1.1
# title "Ensure permissions on bootloader config are configured (Scored)"
# desc "Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them." 
# describe command("stat /boot/grub/grub.conf") do
# its('stdout') { should match /Access: (0600\/-rw-------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
# end
#end
#comment1

control "cis-1-4-3" do
 impact 1.1
 title "Ensure authentication required for single user mode (Scored)"
 desc "Requiring authentication in single user mode prevents an unauthorized user from rebooting the system into single user to gain root privileges without credentials."
 describe command('grep ^SINGLE /etc/sysconfig/init') do
  its('stdout') {should match /SINGLE=\/sbin\/sulogin/}
 end
end

control "cis-1-4-4" do 
 impact 1.1
 title "Ensure interactive boot is not enabled (Scored)"
 desc "Turn off the PROMPT option on the console to prevent console users from potentially overriding established security settings."
 describe command('grep "^PROMPT=" /etc/sysconfig/init') do 
  its('stdout') { should match /PROMPT=no/} 
 end
end

control "cis-1-5-1" do 
 impact 1.1
 title "Ensure core dumps are restricted (Scored)"
 desc "Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5) ). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core."
 describe command('grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*') do 
  its('stdout') {should match /\* hard core 0/}
 end
 describe command('sysctl fs.suid_dumpable') do
  its('stdout') {should match /fs.suid_dumpable = 0/} 
 end
end

control "cis-1-5-2" do
 impact 1.1
 title "Ensure XD/NX support is enabled (Not Scored)"
 desc "Enabling any feature that can protect against buffer overflow attacks enhances the security of the system."
 describe command('dmesg | grep NX') do 
  its('stdout') {should match /NX (Execute Disable) protection: active/}
 end
end

control "cis-1-5-3" do
 impact 1.1
 title "Ensure address space layout randomization (ASLR) is enabled (Scored)"
 desc "Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting."
 describe command('sysctl kernel.randomize_va_space') do 
  its('stdout') {should match /kernel.randomize_va_space = 2/}
 end
end

control "cis-1-5-4" do
 impact 1.1
 title "Ensure prelink is disabled (Scored)"
 desc "The prelinking feature can interfere with the operation of AIDE, because it changes binaries. Prelinking can also increase the vulnerability of the system if a malicious user is able to compromise a common library such as libc."
 describe command('rpm -q prelink') do 
  its('stdout') {should match /package prelink is not installed/}
 end
end

control "cis-1-6-1-1" do 
 impact 2.2
 title "Ensure SELinux is not disabled in bootloader configuration (Scored)"
 desc "SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden."
 describe command('grep "^\s*kernel" /boot/grub/grub.conf') do
 its('stdout') {should match //}
 end
end

control "cis-1-6-1-2" do
 impact 2.2
 title "Ensure the SELinux state is enforcing (Scored)"
 desc "SELinux must be enabled at boot time in to ensure that the controls it provides are in effect at all times."
 describe command('grep SELINUX=enforcing /etc/selinux/config') do
  its('stdout') {should match /SELINUX=enforcing/} 
 end
 describe command('sestatus') do 
  its('stdout') {should match /SELinux status: enabled Current mode: enforcing Mode from config file: enforcing/} 
 end
end

control "cis-1-6-3" do
 impact 2.2
 title "Ensure SELinux policy is configured (Scored)"
 desc "Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met."
 describe command('grep SELINUXTYPE=targeted /etc/selinux/config') do
  its('stdout') { should match /SELINUXTYPE=targeted/}
 end
end

control "cis-1-6-1-4" do 
 title "Ensure SETroubleshoot is not installed (Scored)"
 desc "The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled."
 describe command('rpm -q setroubleshoot') do
  its('stdout') {should match /package setroubleshoot is not installed/ }
 end
end

control "cis-1-6-1-5" do
 title "Ensure the MCS Translation Service (mcstrans) is not installed (Scored)"
 desc "Since this service is not used very often, remove it to reduce the amount of potentially vulnerable code running on the system."
 describe command('rpm -q mcstrans') do
   its('stdout') {should match /package mcstrans is not installed/}
 end
end

control "cis-1-6-1-6" do
 title "Ensure no unconfined daemons exist (Scored)"
 desc "Since daemons are launched and descend from the init process, they will inherit the security context label initrc_t . This could cause the unintended consequence of giving the process more permission than it requires."
 describe command("ps -eZ | egrep 'initrc' | egrep -vw 'tr|ps|egrep|bash|awk' | tr ':' ' ' | awk '{ print $NF }'") do
  its('stdout') {should macth //} 
 end
end

control "cis-1-6-2" do
 title "Ensure SELinux is installed (Scored)"
 impact 2.2
 desc "Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available."
 describe command('rpm -q libselinux') do
  its('stdout') {should match /libselinux-/ }
 end
end

control "cis-1-7-1-1" do 
 title "Ensure message of the day is configured properly (Scored)"
 impact 1.1
 desc "Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the  uname -a  command once they have logged in."
 describe command('egrep "(\\v|\\r|\\m|\\s)" /etc/motd') do
 its('stdout') {should match //}
 end
end

control "cis-1-7-1-2" do 
 title "Ensure local login warning banner is configured properly (Not Scored)"
 impact 1.1
 describe command('egrep "(\\v|\\r|\\m|\\s)" /etc/issue') do
 its('stdout') {should match //}
 end
end

control "cis-1-7-1-3" do
 title "Ensure remote login warning banner is configured properly (Not Scored)"
 impact 1.1
 desc "Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the  uname -a  command once they have logged in."
 describe command('egrep "(\\v|\\r|\\m|\\s)" /etc/issue.net') do
  its('stdout') {should match //} 
 end
end

control "cis-1-7-1-4" do
 title "Ensure permissions on /etc/motd are configured (Not Scored)"
 impact 1.1
 desc "If the /etc/motd file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
 describe file('/etc/motd') do
  its('mode') {should cmp '0644'}
  its('owner') { should eq 'root' }
  its('group') { should eq 'root' }
 end
end

control "cis-1-7-1-5" do
 title "Ensure permissions on /etc/issue are configured (Scored)"
 impact 1.1
 desc "If the /etc/issue file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
 describe file('/etc/issue') do
 its('mode') {should cmp '0644'}
  its('owner') { should eq 'root' }
  its('group') { should eq 'root' }
 end
end

control "cis-1-7-1-6" do
 title "Ensure permissions on /etc/issue.net are configured (Not Scored)"
 impact 1.1
 desc "If the /etc/issue.net file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
 describe file('/etc/issue.net') do
  its('mode') {should cmp '0644'}
  its('owner') { should eq 'root' }
  its('group') { should eq 'root' } 
 end
end

control "cis-1-7-2" do
 title "Ensure GDM login banner is configured (Scored)"
 impact 1.1
 desc "Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place"
 describe file('/etc/dconf/profile/gdm') do
 its('content') {should match "user-db:user
system-db:gdm file-db:\/usr\/share\/gdm\/greeter-dconf-defaults" } 
 end
 describe file('/etc/dconf/db/gdm.d/01-banner-message') do
 it { should be_file }
 end
end

control "cis-1-8" do
 title "Ensure updates, patches, and additional security software are installed (Not Scored)"
 impact 1.1
 desc "Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected."
 describe command('yum check-update') do
  its('stdout') {should match //}
 end
end

control "cis-2-1-1" do
 title "Ensure chargen services are not enabled (Scored)"
 impact 1.1
 desc "Disabling this service will reduce the remote attack surface of the system."
 describe command('chkconfig --list') do
  its('stdout') {should match /xinetd based services:\n	chargen-dgram: 	off\n	chargen-stream:	off/ }
 end
end

control "cis-2-1-2" do
 title "Ensure daytime services are not enabled (Scored)"
 impact 1.1
 desc "Disabling this service will reduce the remote attack surface of the system."
 describe command('chkconfig --list') do
  its('stdout') { should match /xinetd based services:\n	chargen-dgram: 	off\n	chargen-stream:	off\n	daytime-dgram: 	off\n	daytime-stream:	off/}
 end
end

control "cis-2-1-3" do
 title "Ensure discard services are not enabled (Scored)"
 impact 1.1
 desc "Disabling this service will reduce the remote attack surface of the system."
 describe command('chkconfig --list') do
  its('stdout') {should match /xinetd based services:\n	chargen-dgram: 	off\n	chargen-stream:	off\n	daytime-dgram: 	off\n	daytime-stream:	off\n	discard-dgram: 	off\n	discard-stream:	off/} 
end
end

control "cis-2-1-4" do
 title "Ensure echo services are not enabled (Scored)"
 impact 1.1
 desc "Disabling this service will reduce the remote attack surface of the system."
 describe command('chkconfig --list') do
  its('stdout') {should match /xinetd based services:\n chargen-dgram:  off\n   chargen-stream: off\n   daytime-dgram:  off\n   daytime-stream: off\n   discard-dgram:  off\n   discard-stream: off\n   echo-dgram:  off\n   echo-stream: off/}
 end
end

control "cis-2-1-5" do
 title "Ensure time services are not enabled (Scored)"
 impact 1.1
 desc "Disabling this service will reduce the remote attack surface of the system."
 describe command('chkconfig --list') do
  its('stdout') {should match /xinetd based services:\n	chargen-dgram: 	off\n	chargen-stream:	off\n	daytime-dgram: 	off\n	daytime-stream:	off\n	discard-dgram: 	off\n	discard-stream:	off\n	echo-dgram:    	off\n	echo-stream:   	off\n	tcpmux-server: 	off\n	time-dgram:    	off\n	time-stream:   	off/}
 end
end

control "cis-2-1-6" do
 title "Ensure rsh server is not enabled (Scored)"
 impact 1.1
 desc "These legacy services contain numerous security exposures and have been replaced with the more secure SSH package."
 describe command('chkconfig --list') do
  its('stdout') {should match /xinetd based services:\n rexec:  off\n   rlogin: off\n   rsh: off/}
 end
end

control "cis-2-1-7" do
 title "Ensure talk server is not enabled (Scored)"
 impact 1.1
 desc "The software presents a security risk as it uses unencrypted protocols for communication."
 describe command('chkconfig --list') do
   its('stdout') { should match /xinetd based services:\n talk:  off/}
 end
end

control "cis-2-1-8" do
 title "Ensure telnet server is not enabled (Scored)"
 impact 1.1
 desc "The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The ssh package provides an encrypted session and stronger security."
 describe command('chkconfig --list') do
   its('stdout') { should match /xinetd based services:\n telnet:  off/}
 end
end

control "cis-2-1-9" do
 title "Ensure tftp server is not enabled (Scored)"
 impact 1.1
 desc "TFTP does not support authentication nor does it ensure the confidentiality or integrity of data. It is recommended that TFTP be removed, unless there is a specific need for TFTP. In that case, extreme caution must be used when configuring the services."
 describe command('chkconfig --list') do
   its('stdout') { should match /tftp:  off/}
 end
end

control "cis-2-1-10" do
 title "Ensure rsync service is not enabled (Scored)"
 impact 1.1
 desc "The rsyncd service presents a security risk as it uses unencrypted protocols for communication." 
 describe command('chkconfig --list') do
   its('stdout') { should match /rsync:  off/}
 end
end

control "cis-2-1-11" do
 title "Ensure rsync service is not enabled (Scored)"
 impact 1.1
 desc "If there are no xinetd services required, it is recommended that the daemon be disabled." 
 describe command('chkconfig --list xinetd') do
   its('stdout') { should match /xinetd         	0:off	1:off	2:off	3:on	4:on	5:on	6:off/}
 end
end

control "cis-2-2-1-1" do
 title "Ensure time synchronization is in use (Not Scored)"
 impact 1.1
 desc "Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations."
 describe command('rpm -q ntp') do
  its('stdout') {should match /ntp-/}
 end
 describe command('rpm -q chrony') do
  its('stdout') { should match /chrony-/}
 end
end

control "cis-2-2-1-2" do
 title "Ensure ntp is configured (Scored)"
 impact 1.1
 desc "If ntp is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
 describe command('grep "^restrict" /etc/ntp.conf') do
   its('stdout') { should match /restrict -4 default kod nomodify notrap nopeer noquery\nrestrict -6 default kod nomodify notrap nopeer noquery/}
 end
end

control "cis-2-2-1-3" do
 title "Ensure chrony is configured (Scored)"
 impact 1.1
 desc "If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly.This recommendation only applies if chrony is in use on the system."
 describe command('grep "^server" /etc/chrony.conf') do 
  its('stdout') {should match /server/}
 end
 describe command('grep ^OPTIONS /etc/sysconfig/chronyd') do
  its('stdout') {should match /OPTIONS="-u chrony"/}
 end
end

control "cis-2-2-2" do
 title "Ensure X Window System is not installed (Scored)"
 desc "Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface."
 impact 1
 describe command('rpm -qa xorg-x11*') do
  its('stdout') {should match //}
 end
end

control "cis-2-2-3" do
 title "Ensure Avahi Server is not enabled (Scored)"
 desc "Automatic discovery of network services is not normally required for system functionality. It is recommended to disable the service to reduce the potential attack surface."
 impact 1.1
 describe command('chkconfig --list avahi-daemon') do
  its('stdout') {should match /avahi-daemon 0:off 1:off 2:off 3:off 4:off 5:off 6:off/} 
 end
end

control "cis-2-2-4" do
 title "Ensure CUPS is not enabled (Scored)"
 desc "If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be disabled to reduce the potential attack surface."
 impact 1.2
 describe command('chkconfig --list cups') do
  its('stdout') {should match /cups                      0:off  1:off  2:off  3:off  4:off  5:off  6:off/}
 end
end

control "cis-2-2-5" do
 title "Ensure DHCP Server is not enabled (Scored)"
 desc "Unless a system is specifically set up to act as a DHCP server, it is recommended that this service be disabled to reduce the potential attack surface."
 impact 1.1
 describe command('chkconfig --list dhcpd') do
  its('stdout') {should match /dhcpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-2-6" do
 title "Ensure LDAP server is not enabled (Scored)"
 desc "If the system will not need to act as an LDAP server, it is recommended that the software be disabled to reduce the potential attack surface."
 impact 1.1
 describe command('chkconfig --list slapd') do
  its('stdout') { should match /slapd 0:off 1:off 2:off 3:off 4:off 5:off 6:off/} 
 end
end

control "cis-2-2-7" do
 title "Ensure NFS and RPC are not enabled (Scored)"
 desc "If the system does not export NFS shares or act as an NFS client, it is recommended that these services be disabled to reduce remote attack surface."
 impact 1.1
 describe command('chkconfig --list nfs') do
 its('stdout') {should match /nfs                       0:off  1:off  2:off  3:off  4:off  5:off  6:off/}
 end
end

control "cis-2-2-8" do 
 title "Ensure DNS Server is not enabled (Scored)"
 impact 1.1
 desc "Unless a system is specifically designated to act as a DNS server, it is recommended that the service be disabled to reduce the potential attack surface."
 describe command('chkconfig --list named') do
  its('stdout') {should match /named 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-2-9" do
 title "Ensure FTP Server is not enabled (Scored)"
 impact 1.1
 desc "FTP does not protect the confidentiality of data or authentication credentials. It is recommended sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the service be disabled to reduce the potential attack surface."
 describe command('chkconfig --list vsftpd') do
  its('stdout') { should match /vsftpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-2-10" do
 title "Ensure HTTP server is not enabled (Scored)"
 impact 1.1
 desc "Unless there is a need to run the system as a web server, it is recommended that the service be disabled to reduce the potential attack surface."
 describe command('chkconfig --list httpd') do
  its('stdout') { should match /httpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-2-11" do
 title "Ensure IMAP and POP3 server is not enabled (Scored)"
 impact 1.1
 desc "Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the service be disabled to reduce the potential attack surface."
 describe command('chkconfig --list dovecot') do
  its('stdout') {should match /dovecot 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-2-12" do
 title "Ensure Samba is not enabled (Scored)"
 impact 1.1
 desc "If there is no need to mount directories and file systems to Windows systems, then this service can be disabled to reduce the potential attack surface."
 describe command('chkconfig --list smb') do
  its('stdout') { should match /smb                       0:off  1:off  2:off  3:off  4:off  5:off  6:off/}
 end
end 

control "cis-2-2-13" do
 title "Ensure HTTP Proxy Server is not enabled (Scored)"
 impact 1.1
 desc "If there is no need for a proxy server, it is recommended that the squid proxy be disabled to reduce the potential attack surface."
 describe command('chkconfig --list squid') do
   its('stdout') { should match /squid 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-2-14" do
 title "Ensure SNMP Server is not enabled (Scored)"
 impact 1.1
 desc "The SNMP server communicates using SNMP v1, which transmits data in the clear and does not require authentication to execute commands. Unless absolutely necessary, it is recommended that the SNMP service not be used."
 describe command('chkconfig --list snmpd') do
  its('stdout') { should match /snmpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-2-15" do
 title "Ensure mail transfer agent is configured for local-only mode (Scored)"
 impact 1.1
 desc "The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems."
 describe command('netstat -an | grep LIST | grep ":25[[:space:]]"') do
  its('stdout') {should match /tcp 0 0 127.0.0.1:25 0.0.0.0:* LISTEN/}
 end
end

control "cis-2-2-16" do
 title "Ensure NIS Server is not enabled (Scored)"
 impact 1.1
 desc "The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be disabled and other, more secure services be used"
 describe command('chkconfig --list ypserv') do
  its('stdout') {should match /ypserv 0:off 1:off 2:off 3:off 4:off 5:off 6:off/}
 end
end

control "cis-2-3-1" do
 title "Ensure NIS Client is not installed (Scored)"
 impact 1.1
 desc "The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed."
 describe command('rpm -q ypbind') do
  its('stdout') {should match //}
 end
end

control "cis-2-3-2" do
 title "Ensure rsh client is not installed (Scored)"
 impact 1.1
 desc "These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh package removes the clients for rsh , rcp and rlogin ."
 describe command('rpm -q rsh') do
  its('stdout') { should match //}
 end
end

control "cis-2-3-3" do
 title "Ensure talk client is not installed (Scored)"
 impact 1.1
 desc "The software presents a security risk as it uses unencrypted protocols for communication."
 describe command('rpm -q talk') do
  its('stdout') { should match //}
 end
end

control "cis-2-3-4" do
 title "Ensure telnet client is not installed (Scored)"
 impact 1.1
 desc "The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions."
 describe command('rpm -q telnet') do
  its('stdout') {should match //}
 end
end

control "cis-2-3-5" do
 title "Ensure LDAP client is not installed (Scored)"
 impact 1.1
 desc "If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface."
 describe command('rpm -q openldap-clients') do
  its('stdout') {should match //}
 end
end

control "cis-3-1-1" do
 title "Ensure IP forwarding is disabled (Scored)"
 impact 1.1
 desc "Setting the flag to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router."
 describe command('sysctl net.ipv4.ip_forward') do
  its('stdout') {should match /net.ipv4.ip_forward = 0/}
 end
end

control "cis-3-1-2" do
 title "Ensure packet redirect sending is disabled (Scored)"
 impact 1.1
 desc "An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system."
 describe command('sysctl net.ipv4.conf.all.send_redirects') do
  its('stdout') {should match /net.ipv4.conf.all.send_redirects = 0/}
 end
 describe command('sysctl net.ipv4.conf.default.send_redirects') do
  its('stdout') {should match /net.ipv4.conf.default.send_redirects = 0/}
 end
end

control "cis-3-2-1" do
 title "Ensure source routed packets are not accepted (Scored)"
 impact 1.1
 desc "Setting net.ipv4.conf.all.accept_source_route and net.ipv4.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this system was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the system as a way to reach the private address systems. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing."
 describe command('sysctl net.ipv4.conf.all.accept_source_route') do
  its('stdout') {should match /net.ipv4.conf.all.accept_source_route = 0/}
 end 
 describe command('sysctl net.ipv4.conf.default.accept_source_route') do
  its('stdout') { should match /net.ipv4.conf.default.accept_source_route = 0/}
 end
end

control "cis-3-2-2" do
 title "Ensure ICMP redirects are not accepted (Scored)"
 impact 1.1
 desc "Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send packets to incorrect networks and allow your system packets to be captured."
 describe command('sysctl net.ipv4.conf.all.accept_redirects') do
  its('stdout') {should match /net.ipv4.conf.all.accept_redirects = 0/}
 end
 describe command('sysctl net.ipv4.conf.default.accept_redirects') do
  its('stdout') {should match /net.ipv4.conf.default.accept_redirects = 0/}
 end
end

control "cis-3-2-3" do
 title "Ensure secure ICMP redirects are not accepted (Scored)"
 impact 1.1
 desc "It is still possible for even known gateways to be compromised. Setting net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table updates by possibly compromised known gateways."
 describe command('sysctl net.ipv4.conf.all.secure_redirects') do
   its('stdout') {should match /net.ipv4.conf.all.secure_redirects = 0/}
 end
 describe command('sysctl net.ipv4.conf.default.secure_redirects') do
   its('stdout') { should match /net.ipv4.conf.default.secure_redirects = 0/}
 end
 end

control "cis-3-2-4" do
 title "Ensure suspicious packets are logged (Scored)"
 impact 1.1
 desc "Enabling this feature and logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their system."
 describe command('sysctl net.ipv4.conf.all.log_martians') do
  its('stdout') {should match /net.ipv4.conf.all.log_martians = 1/}
 end
 describe command('sysctl net.ipv4.conf.default.log_martians') do
  its('stdout') {should match /net.ipv4.conf.default.log_martians = 1/}
 end
end

control "cis-3-2-5" do
 title "Ensure broadcast ICMP requests are ignored (Scored)"
 impact 1.1
 desc "Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied."
 describe command('sysctl net.ipv4.icmp_echo_ignore_broadcasts') do
  its('stdout') {should match /net.ipv4.icmp_echo_ignore_broadcasts = 1/}
 end
end

control "cis-3-2-6" do
 title "Ensure bogus ICMP responses are ignored (Scored)"
 impact 1.1
 desc "Some routers (and some attackers) will send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages."
 describe command('sysctl net.ipv4.icmp_ignore_bogus_error_responses') do
  its('stdout') {should match /net.ipv4.icmp_ignore_bogus_error_responses = 1/}
 end
end

control "cis-3-2-7" do
 title "Ensure Reverse Path Filtering is enabled (Scored)" 
 impact 1.1
 desc "Setting these flags is a good way to deter attackers from sending your system bogus packets that cannot be responded to. One instance where this feature breaks down is if asymmetrical routing is employed. This would occur when using dynamic routing protocols (bgp, ospf, etc) on your system. If you are using asymmetrical routing on your system, you will not be able to enable this feature without breaking the routing."
 describe command('sysctl net.ipv4.conf.all.rp_filter') do
  its('stdout') { should match /net.ipv4.conf.all.rp_filter = 1/}
 end
 describe command('sysctl net.ipv4.conf.default.rp_filter') do
  its('stdout') {should match /net.ipv4.conf.default.rp_filter = 1/}
 end
end

control "cis-3-2-8" do
 title "Ensure TCP SYN Cookies is enabled (Scored)"
 impact 1.1
 desc "Attackers use SYN flood attacks to perform a denial of service attacked on a system by sending many SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. SYN cookies allow the system to keep accepting valid connections, even if under a denial of service attack."
 describe command('sysctl net.ipv4.tcp_syncookies') do
  its('stdout') {should match /net.ipv4.tcp_syncookies = 1/}
 end
end

control "cis-3-3-1" do
 title "Ensure IPv6 router advertisements are not accepted (Scored)"
 impact 1.1
 desc "It is recommended that systems not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
 describe command('sysctl net.ipv6.conf.all.accept_ra') do
  its('stdout') {should match /net.ipv6.conf.all.accept_ra = 0/}
 end
 describe command('sysctl net.ipv6.conf.default.accept_ra') do
 its('stdout') {should match /net.ipv6.conf.default.accept_ra = 0/}
 end
end

control "cis-3-3-2" do
 title "Ensure IPv6 redirects are not accepted (Scored)"
 impact 1.1
 desc "It is recommended that systems not accept ICMP redirects as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
 describe command('sysctl net.ipv6.conf.all.accept_redirects') do
  its('stdout') {should match /net.ipv6.conf.all.accept_redirect = 0/}
 end
 describe command('sysctl net.ipv6.conf.default.accept_redirects') do
  its('stdout') {should match /net.ipv6.conf.default.accept_redirect = 0/}
 end
end

control "cis-3-3-3" do
 title "Ensure IPv6 is disabled (Not Scored)"
 impact 1.1
 desc "If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface of the system."
 describe command('modprobe -c | grep ipv6') do
  its('stdout')  {should match /options ipv6 disable=1/}
 end
end

control "cis-3-4-1" do
 title "Ensure TCP Wrappers is installed (Scored)"
 impact 1.1
 desc "TCP Wrappers provide a good simple access list mechanism to services that may not have that support built in. It is recommended that all services that can support TCP Wrappers, use it."
 describe command('rpm -q tcp_wrappers') do
  its('stdout') {should match /tcp_wrappers-/}
 end
 describe command('rpm -q tcp_wrappers-libs') do
  its('stdout') { should match /tcp_wrappers-libs-/}
 end
end
<<eof
control "cis-3-4-2" do
 title "Ensure /etc/hosts.allow is configured (Scored)"
 impact 1.1
 desc "The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized systems can connect to the system."
 describe command('')
end
eof

control "cis-3-4-3" do
 title "Ensure /etc/hosts.deny is configured (Scored)"
 impact 1.1
 desc "The /etc/hosts.deny file serves as a failsafe so that any host not specified in /etc/hosts.allow is denied access to the system."
 describe command('cat /etc/hosts.deny') do
   its('stdout') {should match /ALL: ALL/}
 end
end

control "cis-3-4-4" do
 title "Ensure permissions on /etc/hosts.allow are configured (Scored)"
 impact 1.1
 desc "It is critical to ensure that the /etc/hosts.allow file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
 describe file('/etc/hosts.allow') do
  its('mode') {should cmp '0644'}
  its('owner') { should eq 'root' }
  its('group') { should eq 'root' }
 end
end

control "cis-3-4-5" do
 title "Ensure permissions on /etc/hosts.deny are configured (Scored)"
 impact 1.1
 desc "It is critical to ensure that the /etc/hosts.deny file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
 describe file('/etc/hosts.deny') do
  its('mode') {should cmp '0644'}
  its('owner') { should eq 'root' }
  its('group') { should eq 'root' }
 end
end

control "cis-3-5-1" do
 title "Ensure DCCP is disabled (Not Scored)"
 impact 1.1
 desc "If the protocol is not required, it is recommended that the drivers not be installed to reduce the potential attack surface."
 describe command('modprobe -n -v dccp') do
   its('stdout') {should match /install \/bin\/true/}
 end
 describe command('lsmod | grep dccp') do
   its('stdout') { should match //}
 end
end

control "cis-3-5-2" do
 title "Ensure SCTP is disabled (Not Scored)"
 impact 1.1
 desc "If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
 describe command('modprobe -n -v sctp') do
  its('stdout') {should match /install \/bin\/true/}
 end
  describe command('lsmod | grep sctp') do
   its('stdout') { should match //}
 end
end

control "cis-3-5-3" do
 title "Ensure RDS is disabled (Not Scored)" 
 impact 1.1
 desc "If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface." 
describe command('modprobe -n -v rds') do
  its('stdout') {should match /install \/bin\/true/}
 end
  describe command('lsmod | grep rds') do
   its('stdout') { should match //}
 end
end

control "cis-3-5-4" do
 title "Ensure TIPC is disabled (Not Scored)"
 impact 1.1
 desc "If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
describe command('modprobe -n -v tipc') do
  its('stdout') {should match /install \/bin\/true/}
 end
  describe command('lsmod | grep tipc') do
   its('stdout') { should match //}
 end
end

control "cis-3-6-1" do
 title "Ensure iptables is installed (Scored)"
 impact 1.1
 desc "iptables is required for firewall management and configuration."
 describe command('rpm -q iptables') do
 its('stdout') {should match /iptables-/}
 end
end

control "cis-3-6-2" do
 title "Ensure default deny firewall policy (Scored)"
 impact 1.1
 desc "With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage."
 describe command('iptables -L') do
  its('stdout') {should match /Chain INPUT (policy DROP)\nChain FORWARD (policy DROP)\nChain OUTPUT (policy DROP)/}
 end
end

control "cis-3-6-3" do
 title "Ensure loopback traffic is configured (Scored)"
 impact 1.1
 desc "Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure."
 describe command('iptables -L INPUT -v -n') do
  its('stdout') {should match /Chain INPUT \(policy DROP 0 packets, 0 bytes\)\npkts bytes target\ndestination\n    0     0 ACCEPT\n    0     0 DROP\nprot opt in     out\nall  --  lo     \*\nall  --  \*      \*\nsource\n0.0.0.0\/0\n127.0.0.0\/8\n0.0.0.0\/0\n0.0.0.0\/0/}
 end
 describe command('iptables -L OUTPUT -v -n') do
  its('stdout') {should match /Chain OUTPUT \(policy DROP 0 packets, 0 bytes\)\n pkts bytes target     prot opt in     out     source\ndestination\n0 0 ACCEPT all -- \* lo 0.0.0.0\/0.0.0.0.0\/0/}
 end
end 

control "cis-3-6-5" do
 title "Ensure firewall rules exist for all open ports (Scored)"
 impact 1.1
 desc "Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports."
 describe command('netstat -ln') do
 its('stdout') { should match /Active Internet connections \(only servers\)\nProto Recv-Q Send-Q Local Address Foreign Address State tcp 0 0 0.0.0.0:22 0.0.0.0:\* LISTEN/}
 end
  describe command('iptables -L INPUT -v -n') do
   its('stdout') {should match /Chain INPUT \(policy DROP 0 packets, 0 bytes\)\n pkts bytes target     prot opt in     out     source\ndestination\n    0     0 ACCEPT\n0 0 DROP\n    0     0 ACCEPT\ntcp dpt:22 state NEW\nall  --  lo     \*\nall  --  \*      \*\ntcp  --  \*      \*\n0.0.0.0\/0\n127.0.0.0\/8\n0.0.0.0\/0\n0.0.0.0\/0\n0.0.0.0\/0\n0.0.0.0\/0/} 
  end 
end

 
control "cis-4-1-1-1" do
 title "Ensure audit log storage size is configured (Not Scored)"
 impact 2.2
 desc "It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost."
 describe command('grep max_log_file /etc/audit/auditd.conf') do
 its('stdout') {should match /max_log_file = /}
 end
end

control "cis-4-1-1-2" do
 title "Ensure system is disabled when audit logs are full (Scored)" 
 impact 2.2
 desc "In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability."
 describe command('grep space_left_action /etc/audit/auditd.conf') do
  its('stdout') {should match /space_left_action = email/}
 end
  describe command('grep action_mail_acct /etc/audit/auditd.conf') do
  its('stdout') {should match /action_mail_acct = root/}
 end
 describe command('grep admin_space_left_action /etc/audit/auditd.conf') do
  its('stdout') {should match /admin_space_left_action = halt/} 
 end
end

control "cis-4-1-1-3" do
 title "Ensure audit logs are not automatically deleted (Scored)"
 impact 2.2
 desc "In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history."
 describe command('grep max_log_file_action /etc/audit/auditd.conf') do
  its('stdout') { should match /max_log_file_action = keep_logs/}
 end
end

control "cis-4-1-2" do
 title "Ensure auditd service is enabled (Scored)"
 impact 2.2
 desc "The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring."
 describe command('chkconfig --list auditd') do
  its('stdout') { should match /auditd                    0:off  1:off  2:on   3:on   4:on   5:on   6:off/}
 end
end

control "cis-4-1-3" do
 title "Ensure auditing for processes that start prior to auditd is enabled (Scored)"
 impact 2.2
 desc "Audit events need to be captured on processes that start up prior to auditd , so that potential malicious activity cannot go undetected."
 describe command('grep "^\s*kernel" /boot/grub/grub.conf') do
  its('stdout') {should match /audit=1/}
 end
end
<<eof
control "cis-4-1-4" do
 title "Ensure events that modify date and time information are collected (Scored)"
 impact 2.2
 desc  "Unexpected changes in system date and/or time could be a sign of malicious activity on the system."
 describe command('grep time-change /etc/audit/audit.rules') do
  its('stdout') {should match /-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-\nchange\n-a always,exit -F arch=b32 -S clock_settime -k time-change -w \/etc\/localtime -p wa -k time-change/}
 end
 describe command('grep time-change /etc/audit/audit.rules') do
  its('stdout') { should match /-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change\n-a always,exit -F arch=b64 -S clock_settime -k time-change\n-a always,exit -F arch=b32 -S clock_settime -k time-change\n-w \/etc\/localtime -p wa -k time-change/}
 end
end
eof

control "cis-4-1-5" do
 title "Ensure events that modify user/group information are collected (Scored)"
 impact 2.2
 desc "Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts."
 describe command('grep identity /etc/audit/audit.rules') do
  its('stdout') { should match /-w \/etc\/group -p wa -k identity\n-w \/etc\/passwd -p wa -k identity\n-w \/etc\/gshadow -p wa -k identity\n-w \/etc\/shadow -p wa -k identity\n-w \/etc\/security\/opasswd -p wa -k identity/}
 end
end

control "cis-4-1-6" do
 title "Ensure events that modify the system's network environment are collected (Scored)"
 impact 2.2
 desc "Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname of a system. The changing of these names could potentially break security parameters that are set based on those names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is trying to change machine associations with IP addresses and trick users and processes into connecting to unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network is important as it can show if network interfaces or scripts are being modified in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with the identifier system-locale."
 describe command('grep system-locale /etc/audit/audit.rules') do
 its('stdout') { should match /-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale -w \/etc\/issue -p wa -k system-locale\n-w \/etc\/issue.net -p wa -k system-locale\n-w \/etc\/hosts -p wa -k system-locale\n-w \/etc\/sysconfig\/network -p wa -k system-locale/} 
end
 describe command('grep system-locale /etc/audit/audit.rules') do
  its('stdout') { should match /-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale -w \/etc\/issue -p wa -k system-locale\n-w \/etc\/issue.net -p wa -k system-locale\n-w \/etc\/hosts -p wa -k system-locale\n-w \/etc\/sysconfig\/network -p wa -k system-locale/}
 end
end

control "cis-4-1-7" do
 title "Ensure events that modify the system's Mandatory Access Controls are collected (Scored)"
 impact "2.2"
 desc "Changes to files in these directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system."
 describe command('grep MAC-policy /etc/audit/audit.rules') do
  its('stdout') { should match /-w \/etc\/selinux\/ -p wa -k MAC-policy/}
 end
end

control "cis-4-1-8" do
 title  "Ensure login and logout events are collected (Scored)"
 impact 2.2
 desc "Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins."
 describe command('grep logins /etc/audit/audit.rules') do
  its('stdout') { should match /-w \/var\/log\/lastlog -p wa -k logins\n-w \/var\/run\/faillock\/ -p wa -k logins/}
 end
end

control "cis-4-1-9" do
 title "Ensure session initiation information is collected (Scored)"
 impact 2.2
 desc "Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally log in)."
 describe command('grep session /etc/audit/audit.rules') do
  its('stdout') { should match /-w \/var\/run\/utmp -p wa -k session\n-w \/var\/log\/wtmp -p wa -k session\n-w \/var\/log\/btmp -p wa -k session/}
 end
end

control "cis-4-1-10" do
 title "Ensure discretionary access control permission modification events are collected (Scored)"
 impact 2.2
 desc "Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation."
 describe command('grep perm_mod /etc/audit/audit.rules') do
  its('stdout') {should match /-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod/}
 end
 describe command('grep perm_mod /etc/audit/audit.rules') do
  its('stdout') { should match /-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod/}
 end
end

control "cis-4-1-11" do
 title "Ensure unsuccessful unauthorized file access attempts are collected (Scored)"
 impact 2.2
 desc "Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system."
 describe command('grep access /etc/audit/audit.rules') do
  its('stdout') {should match /-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access/}
 end
 describe command('grep access /etc/audit/audit.rules')do
  its('stdout') { should match /-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access/}
 end
end

<<eof
control "cis-4-1-12" do
 title "Ensure use of privileged commands is collected (Scored)"
 impact 2.2
 desc "Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system."
 describe command('') do
  
 end
eof

control "cis-4-1-13" do
 title "Ensure successful file system mounts are collected (Scored)"
 impact 2.2
 desc "It is highly unusual for a non privileged user to mount file systems to the system. While tracking mount commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exported to the media. System administrators who wish to determine if data were exported, would also have to track successful open , creat and truncate system calls requiring write access to a file under the mount point of the external media file system. This could give a fair indication that a write occurred. The only way to truly prove it, would be to track successful writes to the external media. Tracking write system calls could quickly fill up the audit log and is not recommended. Recommendations on configuration options to track data export to media is beyond the scope of this document."
 describe command('grep mounts /etc/audit/audit.rules') do
  its('stdout') { should match /-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts/}
 end
describe command('grep mounts /etc/audit/audit.rules') do
 its('stdout') { should match /-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts\n-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts/}
 end
end

control "cis-4-1-14" do
 title " Ensure file deletion events by users are collected (Scored)"
 impact 2.2
 desc "Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system administrators will want to look for specific privileged files that are being deleted or altered."
 describe command('grep delete /etc/audit/audit.rules') do
  its('stdout') { should match /-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete/}
 end
 describe command('grep delete /etc/audit/audit.rules') do
  its('stdout') { should match /-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete\n-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete/}
 end
end

control "cis-4-1-15" do
 title "Ensure changes to system administration scope (sudoers) is collected (Scored)"
 impact 2.2
 desc "Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope of system administrator activity."
 describe command('grep scope /etc/audit/audit.rules') do
  its('stdout') { should match /-w \/etc\/sudoers -p wa -k scope\n-w \/etc\/sudoers.d -p wa -k scope/}
 end
end

control "cis-4-1-16" do
 title "Ensure system administrator actions (sudolog) are collected (Scored)" 
 impact 2.2
 desc "Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file itself has been tampered with. Administrators will want to correlate the events written to the audit trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed." 
describe command('grep actions /etc/audit/audit.rules') do
  its('stdout') { should match /-w \/var\/log\/sudo.log -p wa -k actions/}
 end
end

control "cis-4-1-17" do
 title "Ensure kernel module loading and unloading is collected (Scored)"
 impact 2.2
 desc "Monitoring the use of insmod , rmmod and modprobe could provide system administrators with evidence that an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting to use a different program to load and unload modules."
 describe command('grep modules /etc/audit/audit.rules') do
 its('stdout') {should match /-w \/sbin\/insmod -p x -k modules\n-w \/sbin\/rmmod -p x -k modules\n-w \/sbin\/modprobe -p x -k modules\n-a always,exit arch=b32 -S init_module -S delete_module -k modules/}
 end
 describe command('grep modules /etc/audit/audit.rules') do
  its('stdout')  { should match /-w \/sbin\/insmod -p x -k modules\n-w \/sbin\/rmmod -p x -k modules\n-w \/sbin\/modprobe -p x -k modules\n-a always,exit arch=b64 -S init_module -S delete_module -k modules/}
 end
end

control "cis-4-1-18" do
 title "Ensure the audit configuration is immutable (Scored)"
 impact 2.2
 desc "In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes."
 describe command('grep "^\s*[^#]" /etc/audit/audit.rules | tail -1') do
 its('stdout') { should match /-e 2/}
 end
end

control "cis-4-2-1-1" do
 title "Ensure rsyslog Service is enabled (Scored)"
 impact 1.1
 desc "If the rsyslog service is not activated the system may default to the syslogd service or lack logging instead."
 describe command('chkconfig --list rsyslog') do
  its('stdout') {should match /rsyslog 0:off 1:off 2:on 3:on 4:on 5:on 6:off/}
 end
end

control "cis-4-2-1-2" do
 title " Ensure logging is configured (Not Scored)"
 impact 1.1
 desc "A great deal of important security-related information is sent via rsyslog (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.)."
 describe command('ls -l /var/log/') do
 its('stdout') {should match //}
 end
end

control "cis-4-2-1-3" do
 title "Ensure rsyslog default file permissions configured (Scored)"
 impact 1.1
 desc "It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected."
 describe command('grep ^\$FileCreateMode /etc/rsyslog.conf') do
  its('stdout') {should match //} 
 end 
end

control "cis-4-2-1-4" do
 title "Ensure rsyslog is configured to send logs to a remote log host (Scored)"
 impact 1.1
 desc "Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system"
 describe command('grep "^*.*[^I][^I]*@" /etc/rsyslog.conf') do
  its('stdout') { should match /\*.\* @@loghost.example.com/}
 end
end

control "cis-4-2-1-5" do
 title "Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)"
 impact 1.1
 desc "The guidance in the section ensures that remote log hosts are configured to only accept rsyslog data from hosts within the specified domain and that those systems that are not designed to be log hosts do not accept any remote rsyslog messages. This provides protection from spoofed log data and ensures that system administrators are reviewing reasonably complete syslog data in a central location."
 describe command('grep "$ModLoad imtcp.so" /etc/rsyslog.conf') do
  its('stdout') {should match /\$ModLoad imtcp.so/}
 end
 describe command('grep $InputTCPServerRun /etc/rsyslog.conf') do
  its('stdout') { should match /\$InputTCPServerRun 514/}
 end
end

control "cis-4-2-2-2" do
 title "Ensure syslog-ng service is enabled (Scored)"
 impact 1.1
 desc "If the syslog-ng service is not activated the system may default to the syslogd service or lack logging instead."
 describe command('chkconfig --list syslog-ng') do
  its('stdout') { should match /syslog-ng 0:off 1:off 2:on 3:on 4:on 5:on 6:off/}
 end
end

control "cis-4-2-2-3" do
 title "Ensure syslog-ng default file permissions configured (Scored)"
 impact 1.1
 desc "It is important to ensure that log files exist and have the correct permissions to ensure that sensitive syslog-ng data is archived and protected."
 describe command('grep ^options /etc/syslog-ng/syslog-ng.conf') do
  its('stdout') { should match /options { chain_hostnames\(off\); flush_lines\(0\); perm\(0640\); stats_freq\(3600\); threaded\(yes\); };/}
 end
end
<<eof
control "cis-4-2-2-4" do
 title "Ensure syslog-ng is configured to send logs to a remote log host (Not Scored)"
 impact 1.1
 desc "Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system"
 describe command('')
end
eof

control "cis-4-2-3" do
 title "Ensure rsyslog or syslog-ng is installed (Scored)"
 impact 1.1
 desc "The security enhancements of rsyslog and syslog-ng such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server) justify installing and configuring the package."
 describe command('rpm -q rsyslog') do
  its('stdout') { should match /rsyslog-/}
 end
 describe command('rpm -q syslog-ng') do
  its('stdout') { should match /syslog-ng-/}
 end
end

control "cis-5-1-1" do
 title "Ensure cron daemon is enabled (Scored)"
 impact 1.1
 desc "While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and cron is used to execute them."
 describe command('chkconfig --list crond') do
 its('stdout') {should match /crond 0:off 1:off 2:on 3:on 4:on 5:on 6:off/}
 end
end

control "cis-5-1-2" do
 title "Ensure permissions on /etc/crontab are configured (Scored)"
 impact 1.1
 desc "This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access."
 describe command('stat /etc/crontab') do
  its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
end

control "cis-5-1-3" do
 title "Ensure permissions on /etc/cron.hourly are configured (Scored)"
 impact 1.1
 desc "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
 describe command('stat /etc/cron.hourly') do
  its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
end

control "cis-5-1-4" do
 title "Ensure permissions on /etc/cron.daily are configured (Scored)"
 impact 1.1
 desc "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
 describe command('stat /etc/cron.daily') do
 its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
end

control "cis-5-1-5" do
 title "Ensure permissions on /etc/cron.weekly are configured (Scored)"
 impact 1.1
 desc "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
 describe command('stat /etc/cron.weekly') do
  its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
end

control "cis-5-1-6" do
 title "Ensure permissions on /etc/cron.monthly are configured (Scored)"
 impact 1.1
 desc "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
 describe command('stat /etc/cron.monthly') do
  its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
end

control "cis-5-1-7" do
 title "Ensure permissions on /etc/cron.d are configured (Scored)"
 impact 1.1
 desc "Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
 describe command('stat /etc/cron.d') do
  its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
end

control "cis-5-1-8" do
 title "Ensure at/cron is restricted to authorized users (Scored)"
 impact 1.1
 desc "On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files."
 describe command('stat /etc/cron.deny') do
  its('stdout') {should match /stat: cannot stat `\/etc\/cron.deny': No such file or directory/} 
 end
 describe command('stat /etc/at.deny') do
  its('stdout') { should macth /stat: cannot stat` \/etc\/at.deny': No such file or directory/}
 end
 describe command('stat /etc/cron.allow') do
   its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
 describe command('stat /etc/at.allow') do
  its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end
end

control "cis-5-2-1" do
 title "Ensure permissions on /etc/ssh/sshd_config are configured (Scored)"
 impact 1.1
 desc "The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non- privileged users, but needs to be readable as this information is used with many non- privileged programs."
 describe command('stat /etc/ssh/sshd_config') do
  its('stdout') { should match /Access: \(0600\/-rw-------\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/}
 end 
end

control "cis-5-2-2" do
 title "Ensure SSH Protocol is set to 2 (Scored)"
 impact 1.1
 desc "SSH v1 suffers from insecurities that do not affect SSH v2."
 describe command('grep "^Protocol" /etc/ssh/sshd_config') do
  its('stdout') { should match /Protocol 2/}
 end
end

control "cis-5-2-3" do
 title "Ensure SSH LogLevel is set to INFO (Scored)"
 impact 1.1
 desc "SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically not recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information. INFO level is the basic level that only records login activity of SSH users. In many situations, such as Incident Response, it is important to determine when a particular user was active on a system. The logout record can eliminate those users who disconnected, which helps narrow the field."
 describe command('grep "^LogLevel" /etc/ssh/sshd_config') do
  its('stdout') { should match /LogLevel INFO/}
 end
end

control "cis-5-2-4" do
 title " Ensure SSH X11 forwarding is disabled (Scored)"
 impact 1.1
 desc "Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders."
 describe command('grep "^X11Forwarding" /etc/ssh/sshd_config') do
  its('stdout') { should match /X11Forwarding no/}
 end
end

control "cis-5-2-5" do
 title "Ensure SSH MaxAuthTries is set to 4 or less (Scored)"
 impact 1.1
 desc "Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, set the number based on site policy."
 describe command('grep "^MaxAuthTries" /etc/ssh/sshd_config') do
  its('stdout') { should match /MaxAuthTries 4/ }
 end
end

control "cis-5-2-6" do
 title "Ensure SSH IgnoreRhosts is enabled (Scored)"
 impact 1.1
 desc "Setting this parameter forces users to enter a password when authenticating with ssh."
 describe command('grep "^IgnoreRhosts" /etc/ssh/sshd_config') do
  its('stdout') { should match /IgnoreRhosts yes/}
 end
end

control "cis-5-2-7" do
 title "Ensure SSH HostbasedAuthentication is disabled (Scored)"
 impact 1.1
 desc "Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf , disabling the ability to use .rhosts files in SSH provides an additional layer of protection ."
 describe command('grep "^HostbasedAuthentication" /etc/ssh/sshd_config') do
  its('stdout') { should match /HostbasedAuthentication no/}
 end
end

control "cis-5-2-8" do
 title "Ensure SSH root login is disabled (Scored)"
 impact 1.1
 desc "Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su . This in turn limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident"
 describe command('grep "^PermitRootLogin" /etc/ssh/sshd_config') do
  its('stdout') { should match /PermitRootLogin no/}
 end
end

control "cis-5-2-9" do
 title "Ensure SSH PermitEmptyPasswords is disabled (Scored)"
 impact 1.1
 desc "Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system"
 describe command('grep "^PermitEmptyPasswords" /etc/ssh/sshd_config') do
  its('stdout') { should match /PermitEmptyPasswords no/}
 end
end

control "cis-5-2-10" do
 title "Ensure SSH PermitUserEnvironment is disabled (Scored)"
 imapct 1.1
 desc "Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has ssh executing trojan'd programs)"
 describe command('grep PermitUserEnvironment /etc/ssh/sshd_config') do
  its('stdout') { should match /PermitUserEnvironment no/}
 end
end

control "cis-5-2-11" do
 title "Ensure only approved ciphers are used (Scored)"
 impact 1.1
 desc "Based on research conducted at various institutions, it was determined that the symmetric portion of the SSH Transport Protocol (as described in RFC 4253) has security weaknesses that allowed recovery of up to 32 bits of plaintext from a block of ciphertext that was encrypted with the Cipher Block Chaining (CBD) method. From that research, new Counter mode algorithms (as described in RFC4344) were designed that are not vulnerable to these types of attacks and these algorithms are now recommended for standard use."
 describe command('grep "Ciphers" /etc/ssh/sshd_config') do
   its('stdout') { should match /Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128- gcm@openssh.com,chacha20-poly1305@openssh.com/}
 end
end

control "cis-5-2-12" do
 title "Ensure only approved MAC algorithms are used (Scored)"
 desc "MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability in SSH downgrade attacks. Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and capture credentials and information"
 describe command('grep "MACs" /etc/ssh/sshd_config') do
  its('stdout') { should match /MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128- etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,curve25519- sha256@libssh.org,diffie-hellman-group-exchange-sha256/ }
 end
end

control "cis-5-2-13" do
 title "Ensure SSH Idle Timeout Interval is configured (Scored)"
 impact 1.1
 desc "Having no timeout value associated with a connection could allow an unauthorized user access to another user's ssh session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout value at least reduces the risk of this happening..
While the recommended setting is 300 seconds (5 minutes), set this timeout value based on site policy. The recommended setting for ClientAliveCountMax is 0. In this case, the client session will be terminated after 5 minutes of idle time and no keepalive messages will be sent."
 describe command('grep "^ClientAliveInterval" /etc/ssh/sshd_config') do
  its('stdout') { should match /ClientAliveInterval 300/}
 end
 describe command('grep "^ClientAliveCountMax" /etc/ssh/sshd_config') do
  its('stdout') { should match /ClientAliveCountMax 0/}
 end
end

control "cis-5-2-14" do
 title "Ensure SSH LoginGraceTime is set to one minute or less (Scored)"
 impact 1.1
 desc "Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. It will also limit the number of concurrent unauthenticated connections While the recommended setting is 60 seconds (1 Minute), set the number based on site policy."
 describe command('grep "^LoginGraceTime" /etc/ssh/sshd_config') do
  its('stdout') { should match /LoginGraceTime 60/}
 end
end

control "cis-5-2-15" do
 title "Ensure SSH access is limited (Scored)"
 impact 1.1
 desc "Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system."
 describe command('grep "^AllowUsers" /etc/ssh/sshd_config') do
  its('stdout') { should match /AllowUsers /}
 end
 describe command('grep "^AllowGroups" /etc/ssh/sshd_config') do
  its('stdout') { should match /AllowGroups /}
 end 
 describe command('grep "^DenyUsers" /etc/ssh/sshd_config') do
  its('stdout') { should match /DenyUsers /}
 end
 describe command('grep "^DenyGroups" /etc/ssh/sshd_config') do
  its('stdout') { should match /DenyGroups /}
 end
end

control "cis-5-2-16" do
 title "Ensure SSH warning banner is configured (Scored)"
 impact 1.1
 desc "Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system."
 describe command('grep "^Banner" /etc/ssh/sshd_config') do
  its('stdout') { should match /Banner \/etc\/issue.net/}
 end
end

control "cis-5-3-1" do
 title "Ensure password creation requirements are configured (Scored)"
 impact 1.1
 desc "Strong passwords protect systems from being hacked through brute force methods."
 describe command('grep pam_cracklib.so /etc/pam.d/password-auth') do
  its('stdout') { should match /password requisite pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=- 1 ucredit=-1 ocredit=-1 lcredit=-1/}
 end
 describe command('grep pam_cracklib.so /etc/pam.d/system-auth') do
  its('stdout') { should match /password requisite pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=- 1 ucredit=-1 ocredit=-1 lcredit=-1/}
 end
end
<<eof
control "cis-5-3-2" do
 title "Ensure lockout for failed password attempts is configured (Scored)"
 impact 1.1
 desc "Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems."
 describe command('')
end
eof

control "cis-5-3-3" do
 title "Ensure password reuse is limited (Scored)"
 impact 1.1
 desc "Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password.
Note that these change only apply to accounts configured on the local system."
 describe command("egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth") do
  its('stdout') {should match /password sufficient pam_unix.so remember=5/} 
 end
 describe command("egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth") do
   its('stdout') { should match /password sufficient pam_unix.so remember=5/}
 end
end

control "cis-5-3-4" do
 title "Ensure password hashing algorithm is SHA-512 (Scored)"
 impact 1.1
 desc "The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords.
Note that these change only apply to accounts configured on the local system."
 describe command("egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth") do
  its('stdout') { should match /password sufficient pam_unix.so sha512/}
 end
 describe command("egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth") do
  its('stdout') { should match /password sufficient pam_unix.so sha512/}
 end
end

control "cis-5-4-1-1" do
 title "Ensure password expiration is 90 days or less (Scored)"
 impact 1.1
 desc "The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity."
 describe command('grep PASS_MAX_DAYS /etc/login.defs') do
  its('stdout') { should match /PASS_MAX_DAYS 90/}
 end
<<eof
 describe command('egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1') do
  its('stdout') { should match / /}
 end
 describe command('chage --list ')
 end
eof
end

control "cis-5-4-1-2" do
 title "Ensure minimum days between password changes is 7 or more (Scored)"
 impact 1.1
 desc "By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls."
 describe command('grep PASS_MIN_DAYS /etc/login.defs') do
   its('stdout') { should match /PASS_MIN_DAYS 7/}
 end
end

control "cis-5-4-1-3" do
 title "Ensure password expiration warning days is 7 or more (Scored)"
 impact 1.1
 desc "Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered."
 describe command('grep PASS_WARN_AGE /etc/login.defs') do
   its('stdout') { should match /PASS_WARN_AGE 7/}
 end
end

control "cis-5-4-1-4" do 
 title "Ensure inactive password lock is 30 days or less (Scored)"
 impact 1.1
 desc "Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies."
 describe command('useradd -D | grep INACTIVE') do
  its('stdout') { should match /INACTIVE=30/}
 end
end

control "cis-5-4-2" do
 title "Ensure system accounts are non-login (Scored)"
 impact 1.1
 desc "It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, CentOS 6 sets the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to /sbin/nologin . This prevents the account from potentially being used to run any commands."
 describe command('egrep -v "^\+" /etc/passwd | awk -F: "($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false") {print}"') do
  its('stdout') {should match //}
 end
end

control "cis-5-4-3" do
 title "Ensure default group for the root account is GID 0 (Scored)"
 impact 1.1
 desc "Using GID 0 for the root account helps prevent root -owned files from accidentally becoming accessible to non-privileged users."
 describe command('grep "^root:" /etc/passwd | cut -f4 -d:') do
  its('stdout') { should match /0/}
 end
end

control "cis-5-4-4" do
 title "Ensure default user umask is 027 or more restrictive (Scored)"
 impact 1.1
 desc "Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions. A default umask setting of 077 causes files and directories created by users to not be readable by any other user on the system. A umask of 027 would make files and directories readable by users in the same Unix group, while a umask of 022 would make files readable by every user on the system."
 describe command('grep "^umask" /etc/bashrc') do
  its('stdout') { should match /umask 027/}
 end
 describe command('grep "^umask" /etc/profile') do
  its('stdout') { should match /umask 027/}
 end
end

control "cis-5-6" do
 title "Ensure access to the su command is restricted (Scored)"
 impact 1.1
 desc "Restricting the use of su , and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo , whereas su can only record that a user executed the su program."
 describe command('grep pam_wheel.so /etc/pam.d/su') do
  its('stdout') {should match /auth required pam_wheel.so use_uid/}
 end
 describe command('grep wheel /etc/group') do
  its('stdout') { should match /wheel:x:10:root,/}
 end
end

control "cis-6-1-1" do
 title "Audit system file permissions (Not Scored)"
 impact 2.2
 desc "It is important to confirm that packaged system files and directories are maintained with the permissions they were intended to have from the OS vendor."
 describe command('rpm -Va --nomtime --nosize --nomd5 --nolinkto') do
  its('stdout') { should match / /}
 end
end

control "cis-6-1-2" do
 title "Ensure permissions on etc passwd are configured (Scored)"
 impact 1.1
 desc "It is critical to ensure that the etc-passwd file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
 describe command("stat /etc/passwd") do
  its('stdout') { should match /Access: \(0644\/-rw-r--r--\) Uid: \( 0\/ root\) Gid: \( 0\/ root\)/ }
 end
end

control "cis-6-1-3" do
 title "Ensure permissions on etc-shadow are configured (Scored)"
 impact 1.1
 desc "If attackers can gain read access to the etc-shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the etc-shadow file (such as expiration) could also be useful to subvert the user accounts."
 describe command('stat /etc/shadow') do
  its('stdout') { should match /Access: (0000\/----------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
 end
end

control "cis-6-1-4" do
 title "Ensure permissions on etc-group are configured (Scored)"
 impact 1.1
 desc "The etc-group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs."
 describe command('stat /etc/group') do
  its('stdout') { should match /Access: (0644\/-rw-r--r--) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
 end
end

control "cis-6-1-5" do
 title "Ensure permissions on etc-gshadow are configured (Scored)"
 impact 1.1
 desc "If attackers can gain read access to the etc-gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the etc-gshadow file (such as group administrators) could also be useful to subvert the group."
 describe command('stat /etc/gshadow') do
  its('stdout') { should match /Access: (0600\/-rw-------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
 end
end

control "cis-6-1-6" do
 title "Ensure permissions on etc-passwd- are configured (Scored)"
 impact 1.1
 desc "It is critical to ensure that the etc-passwd file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
 describe command('stat /etc/passwd-') do
  its('stdout') { should match /Access: (0600\/-rw-------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}  
 end
end

control "cis-6-1-7" do
 title "Ensure permissions on etc-shadow- are configured (Scored)"
 impact 1.1
 desc "It is critical to ensure that the etc-shadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
 describe command('stat /etc/shadow-') do
  its('stdout') { should match /Access: (0600\/-rw-------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
 end
end

control "cis-6-1-8" do
 title "Ensure permissions on etc-group- are configured (Scored)"
 impact 1.1
 desc "It is critical to ensure that the etc-group- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
 describe command('stat /etc/group-') do
  its('stdout') { should match /Access: (0600\/-rw-------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
 end
end

control "cis-6-1-9" do
 title "stat etc-gshadow-"
 impact 1.1
 desc "It is critical to ensure that the etc-gshadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
 describe command('stat /etc/gshadow-') do
  its('stdout') { should match /Access: (0600\/-rw-------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
 end
end

control "cis-6-1-10" do
 title "Ensure no world writable files exist (Scored)"
 impact 1.1
 desc "Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity."
 describe command("df --local -P | awk if (NR!=1) print $6 | xargs -I '{}' find '{}' -xdev -") do
  its('stdout') { should match /type f -perm -0002/}
 end
end

control "cis-6-1-11" do
 title "Ensure no unowned files or directories exist (Scored)"
 impact 1.1
 desc "A new user who is assigned the deleted user's user ID or group ID may then end up "owning" these files, and thus have more access on the system than was intended."
 describe command("df --local -P | awk if (NR!=1) print $6 | xargs -I '{}' find '{}' -xdev -")  do
  its('stdout') { should match /nouser/}
 end
end

control "cis-6-1-12" do
 title "Ensure no ungrouped files or directories exist (Scored)"
 impact 1.1
 desc "A new user who is assigned the deleted user's user ID or group ID may then end up "owning" these files, and thus have more access on the system than was intended."
 describe command("df --local -P | awk if (NR!=1) print $6 | xargs -I '{}' find '{}' -xdev -") do
   its('stdout') { should match /nogroup/}
 end
end

control "cis-6-1-13" do
 title "Audit SUID executables (Not Scored)"
 impact 1.1
 desc "There are valid reasons for SUID programs, but it is important to identify and review such programs to ensure they are legitimate."
 describe command("df --local -P | awk if (NR!=1) print $6 | xargs -I '{}' find '{}' -xdev -") do
  its('stdout') { should match /type f -perm -4000/}
 end
end

control "cis-6-1-14" do
 title "Audit SGID executables (Not Scored)"
 impact 1.1
 desc "There are valid reasons for SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different md5 checksum than what from the package. This is an indication that the binary may have been replaced."
 describe command("df --local -P | awk if (NR!=1) print $6 | xargs -I '{}' find '{}' -xdev -") do
  its('stdout') { should match /type f -perm -2000/}
 end
end

control "cis-6-2-1" do
 title "Ensure password fields are not empty (Scored)"
 impact 1.1
 desc "An account with an empty password field means that anybody may log in as that user without providing a password."
 describe command("cat /etc/shadow | awk -F: "($2 == "" ) { print $1 " does not have a password "}"") do
  its('stdout') { should match //}
 end
end

control "cis-6-2-2" do
 title "Ensure no legacy + entries exist in /etc/passwd (Scored)"
 impact 1.1
 desc "These entries may provide an avenue for attackers to gain privileged access on the system."
 describe command("grep '^+:' /etc/passwd") do
  its('stdout') { should match //}
 end
end

control "cis-6-2-3" do
 title "Ensure no legacy + entries exist in /etc/shadow (Scored)"
 impact 1.1
 desc "These entries may provide an avenue for attackers to gain privileged access on the system." 
 describe command("grep '^+:' /etc/shadow") do
  its('stdout') { should match //}
 end
end

control "cis-6-2-4" do
 title "Ensure no legacy + entries exist in /etc/shadow (Scored)"
 impact 1.1
 desc "These entries may provide an avenue for attackers to gain privileged access on the system."
 describe command("grep '^+:' /etc/group") do
  its('stdout') { should match //}
 end
end

control "cis-6-2-5" do
 title "Ensure root is the only UID 0 account (Scored)"
 impact 1.1
 desc "This access must be limited to only the default root account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure access to the su command is restricted."
 describe command("cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'") do
  its('stdout') { should match /root/}
 end
end

control "cis-6-2-6" do
 title "Ensure root PATH Integrity (Scored)"
  impact 1.1
  desc "Including the current working directory (.) or other writable directory in root 's executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program."
   describe bash('script_6-2-6') do
     its('stdout') { should match //}
    end
end

control "cis-6-2-7" do
 title "Ensure all users' home directories exist (Scored)"
  impact 1.1
  desc "If the user's home directory does not exist or is unassigned, the user will be placed in "/" and will not be able to write any files or have local environment variables set."
   describe bash('script-6-2-7') do
     its('stdout') { should match //}
    end
end

control "cis-6-2-8" do
 title "Ensure users' home directories permissions are 750 or more restrictive (Scored)"
  impact 1.1
  desc "Group or world-writable user home directories may enable malicious users to steal or modify other users' data or to gain another user's system privileges."
  describe bash('script-6-2-8') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-9" do
 title "Ensure users own their home directories (Scored)"
  impact 1.1
  desc "Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory."
  describe bash('script-6-2-9') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-10" do
 title "Ensure users' dot files are not group or world writable (Scored)"
  impact 1.1
  desc "Group or world-writable user configuration files may enable malicious users to steal or modify other users' data or to gain another user's system privileges."
  describe bash('script-6-2-10') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-11" do
 title "Ensure no users have .forward files (Scored)"
  impact 1.1
  desc "Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred outside the organization. The .forward file also poses a risk as it can be used to execute commands that may perform unintended actions."
  describe bash('script-6-2-11') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-12" do
 title "Ensure no users have .netrc files (Scored)"
  impact 1.1
  desc "The .netrc file presents a significant security risk since it stores passwords in unencrypted form. Even if FTP is disabled, user accounts may have brought over .netrc files from other systems which could pose a risk to those systems."
  describe bash('script-6-2-12') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-13" do
 title "Ensure users' .netrc Files are not group or world accessible (Scored)"
  impact 1.1
   desc ".netrcfiles may contain unencrypted passwords that may be used to attack other systems."
  describe bash('script-6-2-13') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-14" do
 title "Ensure no users have .rhosts files (Scored)"
  impact 1.1
   desc "This action is only meaningful if .rhosts support is permitted in the file /etc/pam.conf . Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf , they may have been brought over from other systems and could contain information useful to an attacker for those other systems."
  describe bash('script-6-2-14') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-15" do
 title "Ensure all groups in /etc/passwd exist in /etc/group (Scored)"
  impact 1.1
   desc "Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security since group permissions are not properly managed."
  describe bash('script-6-2-15') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-16" do
 title "Ensure no duplicate UIDs exist (Scored)"
  impact 1.1
   desc "Users must be assigned unique UIDs for accountability and to ensure appropriate access protections."
  describe bash('script-6-2-16') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-17" do
 title "Ensure no duplicate GIDs exist (Scored)"
  impact 1.1
   desc "User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections."
  describe bash('script-6-2-17') do
    its('stdout') { should macth //}
  end
end

control "cis-6-2-18" do
 title "Ensure no duplicate user names exist (Scored)"
  impact 1.1
   desc "If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in /etc/passwd . For example, if "test4" has a UID of 1000 and a subsequent "test4" entry has a UID of 2000, logging in as "test4" will use UID 1000. Effectively, the UID is shared, which is a security problem."
  describe bash('script-6-2-18') do
    its('stdout') { should macth //}
  end
end   

control "cis-6-2-19" do
 title "Ensure no duplicate group names exist (Scored)"
  impact 1.1
   desc "If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in /etc/group . Effectively, the GID is shared, which is a security problem."
  describe bash('script-6-2-19') do
    its('stdout') { should macth //}
  end
end

