#!/usr/bin/perl -w

use strict;

use ExtUtils::MakeMaker;

require 5.008;

WriteMakefile(
	NAME         => 'Crypt-EAX',
	VERSION_FROM => 'lib/Crypt/EAX.pm',
	INSTALLDIRS  => 'site',
	SIGN         => 1,
	PL_FILES     => { },
	PREREQ_PM    => {
		'Digest::CMAC' => 0.03, # prev versions have a bug
		'Crypt::Ctr' => 0,
	},
);

