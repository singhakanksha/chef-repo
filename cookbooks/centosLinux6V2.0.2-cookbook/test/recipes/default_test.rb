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


