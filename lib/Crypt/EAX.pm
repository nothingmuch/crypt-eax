#!/usr/bin/perl

package Crypt::EAX;
use base qw(Class::Accessor::Fast);

use strict;
use warnings;

our $VERSION = "0.01";

use Carp qw(croak);

use Digest::CMAC;
use Crypt::Ctr::FullWidth;

__PACKAGE__->mk_accessors(qw(N iv omac ctr fatal mode));

sub new {
	my ( $class, @args ) = @_;

	if ( @args == 1 ) {
		@args = ( key => $args[0] );
	} elsif ( @args == 2 and $args[0] ne 'key' ) {
		@args = ( key => $args[0], cipher => $args[1] );
	}

	my %args = ( cipher => "Crypt::Rijndael", fatal => 1, @args );

	my $omac = Digest::CMAC->new( @args{qw(key cipher)} );
	my $ctr =  Crypt::Ctr::FullWidth->new( @args{qw(key cipher)} );

	my $self = $class->SUPER::new({ omac => $omac, ctr => $ctr, iv => undef, fatal => $args{fatal} });

	$self->_init(\%args);

	return $self;
}

sub _cbc_k {
	my ( $self, $m ) = @_;
}

sub reset {
	my $self = shift;
	$self->omac->reset;
	$self->ctr->reset;
	$self->ctr->set_nonce($self->N);
	$self->omac_t(2);
}

sub _init {
	my ( $self, $args ) = @_;

	# in nonvoid context it calls ->digest which resets
	my $N = $self->omac_t( 0, $args->{nonce} || '');
	my $H = $self->omac_t( 1, $args->{header} || '' );

	$self->N($N);
	$self->iv( $N ^ $H );

	$self->reset;

}

sub start {
	my ( $self, $mode ) = @_;
	$self->mode($mode);
}

sub encrypt_parts {
	my ( $self, $plain ) = @_;

	$self->start('encrypting');

   	return ( $self->add_encrypt($plain), $self->finish );
}

sub encrypt {
	my ( $self, $plain ) = @_;
	return join('', $self->encrypt_parts($plain) );
}

sub decrypt_parts {
	my ( $self, $ciphertext, $tag ) = @_;

	$self->start('decrypting');

	my $plain = $self->add_decrypt( $ciphertext );

	if ( $self->finish($tag) ) {
		return $plain;
	} else {
		$self->verification_failed($ciphertext, $plain, $tag);
	}
}

sub decrypt {
	my ( $self, $ciphertext ) = @_;

	my $blocksize = $self->blocksize;

	$ciphertext =~ s/(.{$blocksize})$//s;
	my $tag = $1;

	$self->decrypt_parts( $ciphertext, $tag );
}

sub verification_failed {
	my $self = shift;

	if ( $self->fatal ) {
		croak "Verification of ciphertext failed";
	} else {
		return;
	}
}

sub add_encrypt {
	my ( $self, $plain ) = @_;

	my $ciphertext = $self->ctr->encrypt($plain) || '';

	$self->omac->add( $ciphertext );

	return $ciphertext;
}

sub add_decrypt {
	my ( $self, $ciphertext ) = @_;

	$self->omac->add( $ciphertext );

	my $plain = $self->ctr->decrypt($ciphertext);

	return $plain;
}

sub finish {
	my ( $self, @args ) = @_;

	die "No current mode. Did you forget to call start()?" unless $self->mode;

	my $tag = $self->iv ^ $self->omac->digest;
	$self->reset;

	if ( $self->mode eq 'encrypting' ) {
		return $tag;
	} elsif ( $self->mode eq 'decrypting' ) {
		return 1 if $tag eq $args[0];
		return;
	} else {
		croak "Unknown mode: " . $self->mode;
	}
}

sub omac_t {
	my ( $self, $t, @msg ) = @_;

	my $blocksize = $self->blocksize;
	my $padsize = $blocksize -1;

	my $num = pack("x$padsize C", $t);

	$self->omac->add( $num );

	$self->omac->add( $_ ) for @msg;

	return $self->omac->digest if defined wantarray;
}

sub blocksize {
	my $self = shift;

	$self->omac->{cipher}->blocksize;
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Crypt::EAX - 

=head1 SYNOPSIS

	use Crypt::EAX;

=head1 DESCRIPTION

=cut


