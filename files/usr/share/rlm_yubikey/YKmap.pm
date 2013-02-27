# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package YKmap;

use strict;
use Fcntl qw(:flock :seek);

my $file = '/etc/yubico/rlm/ykmapping';

sub set_file {
	$file = shift;
}

sub _read_data {
	my $data = {};
	if(open(MAP_FILE, $file)) {
		while(my $line = <MAP_FILE>) {
			chomp($line);
			next if $line =~ /^(#|$)/;

			my ($username, $keystring) = split(/:/, $line, 2);
			my @keys = split(/,/, $keystring);
			$data->{$username} = \@keys;
		}
		close(MAP_FILE);
	}
	return $data;
}

# Check if a particular username has an OTP assigned to him/her.
sub has_otp {
	my($username) = @_;
	return exists(_read_data()->{$username});
}

# Checks if the given public id comes from a YubiKey belonging to the 
# given user.
sub key_belongs_to {
	my($public_id, $username, $data) = @_;
	$data = _read_data() unless defined $data;

	foreach my $x (@{$data->{$username}}) {
		if($x eq $public_id) {
			return 1;
		}
	}
	return 0;
}

# Returns the username for the given YubiKey public ID.
sub lookup_username {
	my($public_id) = @_;
	my $data = _read_data();

	foreach my $user (keys $data) {
		if(key_belongs_to($public_id, $user, $data)) {
			return $user;
		}
	}

	return undef;
}

# Can we auto-provision the given YubiKey for the user?
sub can_provision {
	my($public_id, $username) = @_;

	#TODO: Check if key is provisioned to someone else?
	return not exists(_read_data()->{$username});
}

# Provision the given YubiKey to the given user.
sub provision {
	my($public_id, $username) = @_;

	if(open(MAP_FILE,">>$file")) {
		flock(MAP_FILE, LOCK_EX);
		seek(MAP_FILE, 0, SEEK_END); 
		print MAP_FILE "$username:$public_id\n"; 
		close(MAP_FILE);
	} else {
		warn("Unable to provision YubiKey: $public_id to $username!");
	}
}

1;
