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

#control "cis-1-1-2" do
#impact 2.2
#title "Ensure separate partition exists for /tmp (Scored)"
#desc "Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
#describe command("mount | grep /tmp") do
#  its('stdout') { should match /tmpfs on \/tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)/ }
#end
#end

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

control "cis-1-4-1" do
 impact 1.1
 title "Ensure permissions on bootloader config are configured (Scored)"
 desc "Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them." 
 describe command("stat /boot/grub/grub.conf") do
 its('stdout') { should match /Access: (0600\/-rw-------) Uid: ( 0\/ root) Gid: ( 0\/ root)/}
 end
end
