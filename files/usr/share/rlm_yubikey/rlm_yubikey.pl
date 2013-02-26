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

use strict;
use warnings;
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);
use AnyEvent::Yubico;
use Crypt::CBC;
use Error qw(:try);

# Default configuration
our $id_len = 12;
our $verify_urls = [ "http://127.0.0.1/wsapi/2.0/verify" ];
our $client_id = 1;
our $api_key = "";
our $allow_userless_login = 1;
our $allow_single_factor = 1;
our $mapping_file = "/etc/yubico/rlm/ykmapping";

# Load user configuration
do "/etc/yubico/rlm/ykrlm-config.cfg";

# Initialization
my $otp_len = 32 + $id_len;

my $key = Crypt::CBC->random_bytes(128);
my $cipher = Crypt::CBC->new(
	-key => $key,
	-cipher => 'Blowfish',
	-padding => 'space',
	-add_header => 1
);
my $ykval = AnyEvent::Yubico->new({
	client_id => $client_id,
	api_key => $api_key,
	urls	=> $verify_urls
});

########################
# FreeRADIUS functions #
########################

use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant	RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant	RLM_MODULE_OK=>	2;#  /* the module is OK, continue */
use constant	RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant	RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant	RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant	RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant	RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant	RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant	RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */


# Make sure the user has a valid YubiKey OTP
sub authorize {
	# Extract OTP, if available
	my $otp = '';
	if($RAD_REQUEST{'User-Name'} =~ /[cbdefghijklnrtuv]{$otp_len}$/) {
		my $username_len = length($RAD_REQUEST{'User-Name'}) - $otp_len;
		$otp = substr $RAD_REQUEST{'User-Name'}, $username_len;
		$RAD_REQUEST{'User-Name'} = substr $RAD_REQUEST{'User-Name'}, 0, $username_len;
	} elsif($RAD_REQUEST{'User-Password'} =~ /[cbdefghijklnrtuv]{$otp_len}$/) {
		my $password_len = length($RAD_REQUEST{'User-Password'}) - $otp_len;
		$otp = substr $RAD_REQUEST{'User-Password'}, $password_len;
		$RAD_REQUEST{'User-Password'} = substr $RAD_REQUEST{'User-Password'}, 0, $password_len;
	}

	# Check for State, in the case of a previous Access-Challenge.
	if(! $RAD_REQUEST{'State'} eq '') {
		#Restore password from State
		my $state = pack('H*', substr($RAD_REQUEST{'State'}, 2));
		try {
			my $password = decrypt_password($state);
			$RAD_REQUEST{'User-Password'} = $password;
		} catch Error with {
			#State not for us, ignore.
		}
	}

	my $username = $RAD_REQUEST{'User-Name'};
	
	# Handle OTP
	if($otp eq '') {
		# No OTP
		if($username eq '') {
			# No OTP or username, reject
			&radiusd::radlog(1, "Reject: No username or OTP");
			$RAD_REPLY{'Reply-Message'} = "Missing username and OTP!";
			return RLM_MODULE_REJECT;

		} elsif(!$allow_single_factor or requires_otp($username)) {
			$RAD_REPLY{'State'} = encrypt_password($RAD_REQUEST{'User-Password'});
			$RAD_REPLY{'Reply-Message'} = "Please provide YubiKey OTP";
			$RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
			return RLM_MODULE_HANDLED;
		} else {
			# Allow login without OTP
			&radiusd::radlog(1, "$username allowed with no OTP");
			return RLM_MODULE_NOOP;
		}
	} elsif(validate_otp($otp)) {
		&radiusd::radlog(1, "OTP is valid: $otp");
		my $public_id = substr($otp, 0, $id_len);

		#Lookup username if needed/allowed.
		if($username eq '' and $allow_userless_login) {
			$username = lookup_username($public_id);
			&radiusd::radlog(1, "lookup of $public_id gave $username");
			$RAD_REQUEST{'User-Name'} = $username;
		}

		if(key_belongs_to($public_id, $username)) {
			&radiusd::radlog(1, "$username has valid OTP: $otp");
			return RLM_MODULE_OK;
		} elsif(can_provision($public_id, $username)) {
			&radiusd::radlog(1, "Attempt to provision $public_id for $username post authentication");
			$RAD_CHECK{'YubiKey-Provision'} = $public_id;
			return RLM_MODULE_UPDATED;	
		} else {
			&radiusd::radlog(1, "Reject: $username using valid OTP from foreign YubiKey: $public_id");
			$RAD_REPLY{'Reply-Message'} = "Invalid OTP!";
			return RLM_MODULE_REJECT;
		}
	} else {
		#Invalid OTP
		&radiusd::radlog(1, "Reject: $username with invalid OTP: $otp");
		$RAD_REPLY{'Reply-Message'} = "Invalid OTP!";
		return RLM_MODULE_REJECT;
	}
}

# Do auto-provisioning, if needed, after authentication.
sub post_auth {
	my $public_id = $RAD_CHECK{'YubiKey-Provision'};
	my $username = $RAD_REQUEST{'User-Name'};

	if($public_id =~ /^[cbdefghijklnrtuv]{$id_len}$/) {
		provision($public_id, $username);
	}

	return RLM_MODULE_OK;
}

##################
# OTP Validation #
##################

# Validates a YubiKey OTP.
sub validate_otp {
	my($otp) = @_;

	return $ykval->verify($otp);
}


# Encrypts a password using an instance specific key
sub encrypt_password {
	my($plaintext) = @_;

	return $cipher->encrypt($plaintext);
}

# Decrypts a password using an instance specific key
sub decrypt_password {
	my($ciphertext) = @_;

	return $cipher->decrypt($ciphertext);
}

###################
# YubiKey Mapping #
###################

# Simple file based YubiKey mapping:
my $mapping_data = {};
open(my $info, $mapping_file);
while(my $line = <$info>) {
	chomp($line);
	next if $line =~ /^(#|$)/;

	my ($username, $keystring) = split(/:/, $line, 2);
	my @keys = split(/,/, $keystring);
	$mapping_data->{$username} = \@keys;
}

# Check if a particular username requires an OTP to log in.
sub requires_otp {
	my($username) = @_;
	return exists($mapping_data->{$username});
}

# Checks if the given public id comes from a YubiKey belonging to the 
# given user.
sub key_belongs_to {
	my($public_id, $username) = @_;
	foreach my $x (@{$mapping_data->{$username}}) {
		if($x eq $public_id) {
			return 1;
		}
	}
	return 0;
}

# Can we auto-provision the given YubiKey for the user?
sub can_provision {
	my($public_id, $username) = @_;

	#TODO: Insert logic for determining if a YubiKey can be provisioned here
	return 0;
}

# Provision the given YubiKey to the given user.
sub provision {
	my($public_id, $username) = @_;
	
	#TODO: Insert provisioning logic here
	die(1,"Tried to provision $public_id to $username, but provisioning is not supported!");
}

sub lookup_username {
	my($public_id) = @_;

	foreach my $user (keys $mapping_data) {
		if(key_belongs_to($public_id, $user)) {
			return $user;
		}
	}

	return undef;
}

