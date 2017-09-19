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

control "cis-3-4-2" do
 title "Ensure /etc/hosts.allow is configured (Scored)"
 impact 1.1
 desc "The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized systems can connect to the system."
 describe command('')
end
