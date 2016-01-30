package WWW::OAuth::Util;

use Carp 'croak';
use Encode 'decode';
use Exporter 'import';
use List::Util 'pairs';
use Module::Runtime 'require_module';
use Role::Tiny ();
use Scalar::Util 'blessed';
use URI::Escape 'uri_escape_utf8', 'uri_unescape';

our $VERSION = '0.001';

our @EXPORT_OK = qw(oauth_request_from form_urlencode form_urldecode);

sub oauth_request_from {
	my ($class, %args);
	if (blessed $_[0]) { # Request object
		my $req = shift;
		if (Role::Tiny::does_role($req, 'WWW::OAuth::Request')) { # already in container
			return $req;
		} elsif ($req->isa('HTTP::Request')) {
			$class = 'HTTPRequest';
		} elsif ($req->isa('Mojo::Message')) {
			$class = 'Mojo';
		} else {
			$class = blessed $req;
			$class =~ s/:://g;
		}
		%args = (request => $req);
	} elsif (ref $_[0]) { # Hashref for HTTP::Tiny
		my $href = shift;
		$class = 'Basic';
		%args = %$href;
	} else { # Request class and args hashref
		($class, my $href) = @_;
		%args = %$href;
	}
	
	croak 'No request to authenticate' unless defined $class and %args;
	
	$class = "WWW::OAuth::Request::$class" unless $class =~ /::/;
	require_module $class;
	croak "Class $class does not perform the role WWW::OAuth::Request"
		unless Role::Tiny::does_role($class, 'WWW::OAuth::Request');
	
	return $class->new(%args);
}

sub form_urlencode {
	my $form = shift;
	my @params;
	if (ref $form eq 'ARRAY') {
		@params = @$form;
	} elsif (ref $form eq 'HASH') {
		@params = %$form;
	} else {
		croak 'Form to urlencode must be hash or array reference';
	}
	croak 'Form to urlencode must be even-sized' if @params % 2;
	my @pairs;
	foreach my $pair (pairs @params) {
		my $key = $pair->[0];
		my @values = ref $pair->[1] eq 'ARRAY' ? @{$pair->[1]} : $pair->[1];
		do { s/ /+/g; $_ = uri_escape_utf8 $_ } for $key, @values;
		push @pairs, "$key=$_" for @values;
	}
	@pairs = sort @pairs if ref $form eq 'HASH';
	return join '&', @pairs;
}

sub form_urldecode {
	my $string = shift;
	my @form = map { $_ = '' unless defined $_; s/\+/ /g; decode 'UTF-8', uri_unescape($_), Encode::FB_CROAK }
		map { my ($k, $v) = split /=/, $_, 2; ($k, $v) } split /&/, $string;
	return \@form;
}

1;

=head1 NAME

WWW::OAuth::Util - Utility functions for WWW::OAuth

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 METHODS

=head1 BUGS

Report any issues on the public bugtracker.

=head1 AUTHOR

Dan Book <dbook@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2015 by Dan Book.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=head1 SEE ALSO

L<HTTP::Request>, L<Mojo::Message::Request>
