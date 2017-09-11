# # encoding: utf-8

# Inspec test for recipe centosLinux7V2.1.1-cookbook::default

# The Inspec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec_reference.html

control "cis-1-2-2" do
 impact 1.1
 title "Ensure GPG keys are configured (Not Scored)"
 desc "Most packages managers implement GPG key signing to verify package integrity during installation."
 describe command('rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'') do
   its ('stdout') {should match /CentOS 7 Official Signing Key/}
 end
end
