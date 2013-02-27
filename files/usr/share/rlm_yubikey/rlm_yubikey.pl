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

#Add script directory to @INC:
use File::Spec::Functions qw(rel2abs);
use File::Basename;
use lib dirname(rel2abs($0));

# Default configuration
our $id_len = 12;
our $verify_urls = [
	"https://api.yubico.com/wsapi/2.0/verify",
	"https://api2.yubico.com/wsapi/2.0/verify",
	"https://api3.yubico.com/wsapi/2.0/verify",
	"https://api4.yubico.com/wsapi/2.0/verify",
	"https://api5.yubico.com/wsapi/2.0/verify"
];
our $client_id = 10549;
our $api_key = "zeYjxHz+X/d12FAq0av4U9goZHY=";
our $allow_auto_provisioning = 1;
our $allow_userless_login = 1;
our $security_level = 0;
our $mapping_file = undef;

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
	urls => $verify_urls
});

use YKmap;
if(defined $mapping_file) {
	YKmap::set_file($mapping_file);
}

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
		} elsif($security_level eq 2 or ($security_level eq 1 and YKmap::has_otp($username))) {
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
			$username = YKmap::lookup_username($public_id);
			&radiusd::radlog(1, "lookup of $public_id gave $username");
			$RAD_REQUEST{'User-Name'} = $username;
		}

		if(YKmap::key_belongs_to($public_id, $username)) {
			&radiusd::radlog(1, "$username has valid OTP: $otp");
			return RLM_MODULE_OK;
		} elsif($allow_auto_provisioning and YKmap::can_provision($public_id, $username)) {
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
		YKmap::provision($public_id, $username);
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
