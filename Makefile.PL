#!/usr/bin/perl -w

use strict;

use ExtUtils::MakeMaker;

require 5.008;

WriteMakefile(
	NAME         => 'Crypt::EAX',
	VERSION_FROM => 'lib/Crypt/EAX.pm',
	INSTALLDIRS  => 'site',
	SIGN         => 1,
	PL_FILES     => { },
	PREREQ_PM    => {
		'Digest::OMAC2' => 0, # in case CMAC 0.03 doesn't get indexed
		'Digest::CMAC' => 0.03, # prev versions have a bug
		'Crypt::Ctr' => 0,
	},
);

